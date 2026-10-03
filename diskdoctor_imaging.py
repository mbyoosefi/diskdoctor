"""Checkpointed imaging: preserves retry, sector descent and explicit fill."""
import hashlib
import os
import sys
import time
import uuid

import diskdoctor_core as core


def progress(done, total, bad, start, prior=0):
    elapsed = prior + time.monotonic() - start
    rate = done / elapsed if elapsed > 0 else 0
    eta = (total - done) / rate if rate else None
    return {"bytes_processed": done, "total_bytes": total, "bad_bytes": bad,
            "elapsed_seconds": round(elapsed, 3), "rate_bytes_per_second": round(rate, 2),
            "eta_seconds": round(eta, 1) if eta is not None else None}


def checkpoint(directory, doc, previous=None):
    doc = dict(doc, checkpoint_index=0 if previous is None else previous["checkpoint_index"] + 1,
               previous_sha256=None if previous is None else previous["sha256"])
    doc["sha256"] = core.digest(core.canonical(doc))
    core.durable_json(os.path.join(directory, "%08d.json" % doc["checkpoint_index"]), doc)
    return doc


def load_checkpoint(directory):
    last = None
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        doc = core.read_json(os.path.join(directory, name))
        h = doc.get("sha256")
        body = {k: v for k, v in doc.items() if k != "sha256"}
        index = 0 if last is None else last["checkpoint_index"] + 1
        prev = None if last is None else last["sha256"]
        if name != "%08d.json" % index or doc["checkpoint_index"] != index or doc["previous_sha256"] != prev or core.digest(core.canonical(body)) != h:
            raise core.SafetyError("FAILED_JOURNAL", "imaging checkpoint chain tampered")
        last = doc
    if last is None:
        raise core.SafetyError("FAILED_JOURNAL", "no imaging checkpoint")
    return last


def make_image(dd, disk, path, limit=0, chunk=8 * 1024 * 1024, retries=3,
               fill="pat", resume=False, final_hash=False, fault=None):
    if chunk <= 0 or retries <= 0 or limit < 0 or fill not in dd.FILL_PATTERNS:
        raise core.SafetyError("BLOCKED", "invalid imaging parameters")
    fault = fault or (lambda point: None)
    path = os.path.abspath(path)
    from diskdoctor_safety import ensure_destination
    ensure_destination(dd, disk, path)
    if os.path.normcase(os.path.realpath(path)) == os.path.normcase(os.path.realpath(disk.path)):
        raise core.SafetyError("BLOCKED", "output aliases source")
    # Exclusive creation also blocks hardlinks, symlinks and existing images.
    total = disk.size if not limit else min(disk.size, limit)
    directory = path + ".checkpoints"
    previous = None
    done, bad_bytes, bad_ranges = 0, 0, []
    prior, start = 0, time.monotonic()
    h = hashlib.sha256()
    if resume:
        previous = load_checkpoint(directory)
        source = previous["source_fingerprint"]
        core.validate_fingerprint(disk, source)
        if (previous["total_bytes"], previous["fill_pattern"], previous["retries"], previous["chunk"]) != (total, fill, retries, chunk):
            raise core.SafetyError("BLOCKED", "resume parameters differ")
        st = os.stat(path)
        if [st.st_dev, st.st_ino] != previous["output_identity"] or st.st_size < previous["bytes_processed"]:
            raise core.SafetyError("BLOCKED_SOURCE_CHANGED", "imaging output replaced/truncated")
        run_id, done = previous["run_id"], previous["bytes_processed"]
        bad_bytes, bad_ranges = previous["bad_bytes"], previous["bad_ranges"]
        prior = previous["elapsed_seconds"]
        with open(path, "rb") as f:
            remaining = done
            while remaining:
                b = f.read(min(8 * 1024 * 1024, remaining))
                h.update(b)
                remaining -= len(b)
        if h.hexdigest() != previous["output_prefix_sha256"]:
            raise core.SafetyError("BLOCKED_SOURCE_CHANGED", "imaging output prefix changed")
        if previous["state"] == "DONE_CHECKED":
            if st.st_size != total:
                raise core.SafetyError("BLOCKED_SOURCE_CHANGED", "completed output size differs")
            return path, core.read_json(path + ".badmap.json")
        f = open(path, "r+b", buffering=0)
    else:
        if os.path.lexists(path) or os.path.lexists(directory) or os.path.lexists(path + ".badmap.json"):
            raise core.SafetyError("BLOCKED", "imaging output collision; use --image-resume for an interrupted run")
        source = core.fingerprint(disk, tolerate_errors=True)
        run_id = str(uuid.uuid4())
        os.mkdir(directory)
        core.sync_dir(os.path.dirname(directory))
        f = open(path, "xb", buffering=0)
    try:
        with core.transaction_lock(directory):
            # Re-read the latest checkpoint under the exclusive run lock.
            if resume and load_checkpoint(directory) != previous:
                raise core.SafetyError("BLOCKED_SOURCE_CHANGED", "checkpoint changed while acquiring lock")
            st = os.fstat(f.fileno())
            output_identity = [st.st_dev, st.st_ino]

            def record(state):
                nonlocal previous
                f.flush()
                os.fsync(f.fileno())
                previous = checkpoint(directory, dict(
                    progress(done, total, bad_bytes, start, prior), state=state,
                    run_id=run_id, source_fingerprint=source, image=path,
                    output_identity=output_identity, output_prefix_sha256=h.hexdigest(),
                    fill_pattern=fill, retries=retries, chunk=chunk,
                    bad_ranges=bad_ranges, timestamp=core.timestamp()), previous)
            if not resume:
                record("PREPARED")
            else:
                # Bytes after the last synced checkpoint were never committed.
                f.truncate(done)
                f.seek(done)
                os.fsync(f.fileno())
            while done < total:
                n = min(chunk, total - done)
                data = dd._read_retry(disk, done, n, retries)
                if data is not None and len(data) == n:
                    if f.write(data) != n:
                        raise core.SafetyError("FAILED_WRITE", "short image write")
                    h.update(data)
                else:
                    # Preserve sector-level recovery inside an unreadable chunk.
                    for off in range(done, done + n, disk.sector):
                        m = min(disk.sector, done + n - off)
                        b = dd._read_retry(disk, off, m, retries)
                        if b is None or len(b) != m:
                            b = dd._fill_block(fill, m)
                            bad_bytes += m
                            if bad_ranges and bad_ranges[-1]["end"] == off:
                                bad_ranges[-1]["end"] = off + m
                                bad_ranges[-1]["sectors"] += 1
                            else:
                                bad_ranges.append({"start": off, "end": off+m,
                                                   "start_lba": off // disk.sector, "sectors": 1})
                        if f.write(b) != m:
                            raise core.SafetyError("FAILED_WRITE", "short sector image write")
                        h.update(b)
                done += n
                record("IMAGING")
                fault("after_checkpoint")
                stats = progress(done, total, bad_bytes, start, prior)
                if not dd.QUIET:
                    sys.stdout.write("\rPROGRESS %.1f%% RATE %.2f MiB/s ELAPSED %.0fs ETA %s BAD %d " % (
                        100 * done / total, stats["rate_bytes_per_second"] / (1024 * 1024),
                        stats["elapsed_seconds"], stats["eta_seconds"], bad_bytes))
                    sys.stdout.flush()
            core.validate_fingerprint(disk, source, allow_unknown=True)
            if os.fstat(f.fileno()).st_size != total:
                raise core.SafetyError("FAILED_READBACK", "final image size mismatch")
            f.flush()
            os.fsync(f.fileno())
            actual_hash = core.file_hash(path) if final_hash else None
            if actual_hash is not None and actual_hash != h.hexdigest():
                raise core.SafetyError("FAILED_READBACK", "whole image hash mismatch")
            badmap = {"tool": "DiskDoctor", "version": dd.VERSION, "run_id": run_id,
                      "time": core.timestamp(), "source": disk.path, "image": path,
                      "source_fingerprint": source, "sector_size": disk.sector,
                      "imaged_bytes": done, "final_output_size": total,
                      "unreadable_bytes": bad_bytes, "fill_pattern": fill,
                      "retries_per_sector": retries, "bad_ranges": bad_ranges,
                      "sha256": actual_hash, "stream_sha256": h.hexdigest()}
            if os.path.exists(path + ".badmap.json"):
                if core.read_json(path + ".badmap.json").get("stream_sha256") != h.hexdigest():
                    raise core.SafetyError("FAILED_JOURNAL", "badmap collision")
            else:
                core.durable_json(path + ".badmap.json", badmap)
            record("DONE_CHECKED")
            dd.ok("\nDONE/CHECKED: " + path)
            return path, badmap
    finally:
        f.close()
