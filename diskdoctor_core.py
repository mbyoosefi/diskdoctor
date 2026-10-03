"""Fail-closed identity, durable artifacts and append-only sector transactions.

The forensic engine remains in diskdoctor.py. No dependency beyond Python 3.8.
Hash chaining detects alteration relative to the manifest; it is not a signature
and does not protect against an attacker replacing an entire transaction tree.
"""
import contextlib
import ctypes
import datetime
import hashlib
import json
import os
import platform
import uuid

EVIDENCE_STATES = ("VERIFIED", "REJECTED", "INFERRED", "HYPOTHESIS", "UNKNOWN",
                   "PATCHED", "REVERTED", "BLOCKED", "FAILED")
WRITE_CLASSES = ("PROVEN_REDUNDANT_COPY", "PROVEN_RECALCULATION",
                 "PROVEN_GEOMETRY_WITH_PRESERVED_IDENTITY",
                 "OPERATOR_SUPPLIED_RECONSTRUCTION", "INFERRED_GEOMETRY",
                 "AMBIGUOUS", "BLOCKED")
ELIGIBLE = frozenset(WRITE_CLASSES[:4])


class SafetyError(Exception):
    def __init__(self, state, detail=""):
        self.state = state
        self.detail = detail
        super().__init__(state + (": " + detail if detail else ""))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(doc):
    return json.dumps(doc, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sync_dir(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def durable_create(path, data):
    """Exclusive immutable artifact; sync contents and publish durably.

Windows publishes using MoveFileExW(MOVEFILE_WRITE_THROUGH), without replacement.
POSIX syncs the file and its containing directory. Errors are never suppressed.
"""
    path = os.path.abspath(path)
    if os.name == "nt":
        temp = path + ".pending-" + str(uuid.uuid4())
    else:
        temp = path
    with open(temp, "xb", buffering=0) as f:
        if f.write(data) != len(data):
            raise SafetyError("FAILED_DURABILITY", "short artifact write")
        f.flush()
        os.fsync(f.fileno())
    if os.name == "nt":
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        move = k.MoveFileExW
        move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        move.restype = ctypes.c_int
        if not move(temp, path, 0x8):
            raise OSError(ctypes.get_last_error(), "durable exclusive publish", path)
    sync_dir(os.path.dirname(path))
    with open(path, "rb") as f:
        if f.read() != data:
            raise SafetyError("FAILED_BACKUP_VERIFY", path)


def durable_json(path, doc):
    durable_create(path, canonical(doc))


def read_json(path):
    with open(path, "rb") as f:
        return json.load(f)


def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def identity(disk):
    path = os.path.normcase(os.path.realpath(disk.path))
    obj = {"canonical_path": path, "size": disk.size,
           "sector_size": disk.sector, "base_offset": disk.base,
           "kind": "device" if disk.is_device else "image"}
    st = os.stat(disk.path)
    obj.update(filesystem_device=st.st_dev, filesystem_inode=st.st_ino,
               physical_file_size=st.st_size, rdev=getattr(st, "st_rdev", 0))
    if not disk.is_device:
        # An open descriptor must still name the same filesystem object.
        opened = os.fstat(disk.fh.fileno())
        if (st.st_dev, st.st_ino, st.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
            raise SafetyError("BLOCKED_SOURCE_CHANGED", "path/handle identity mismatch")
    provider = getattr(disk, "identity_provider", None)
    if disk.is_device:
        if provider is None:
            raise SafetyError("BLOCKED_UNSUPPORTED_LAYOUT", "stable device identity unavailable")
        obj["device_identity"] = provider()
    return obj


def sample_ranges(disk, regions=()):
    n = min(65536, disk.size)
    ranges = {(0, n), (max(0, disk.size // 2 - n // 2), n),
              (max(0, disk.size - n), n)}
    for off, length in regions:
        if off < 0 or length <= 0 or off + length > disk.size:
            raise SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "fingerprint region out of range")
        ranges.add((off, length))
    return sorted(ranges)


def fingerprint(disk, regions=(), full=False, tolerate_errors=False):
    ident = identity(disk)
    st = os.stat(disk.path)
    samples = []
    for off, length in sample_ranges(disk, regions):
        try:
            data = disk.read_at(off, length)
            if len(data) != length:
                raise SafetyError("BLOCKED_SOURCE_CHANGED", "short fingerprint read")
            samples.append({"offset": off, "length": length, "sha256": digest(data)})
        except Exception:
            if not tolerate_errors:
                raise
            samples.append({"offset": off, "length": length, "sha256": None, "state": "UNKNOWN"})
    doc = {"identity": ident, "mtime_ns": st.st_mtime_ns if not disk.is_device else None,
           "samples": samples, "full_sha256": None}
    if full:
        h = hashlib.sha256()
        pos = 0
        while pos < disk.size:
            n = min(8 * 1024 * 1024, disk.size - pos)
            data = disk.read_at(pos, n)
            if len(data) != n:
                raise SafetyError("BLOCKED_SOURCE_CHANGED", "short full hash read")
            h.update(data)
            pos += n
        doc["full_sha256"] = h.hexdigest()
    doc["sha256"] = digest(canonical(doc))
    return doc


def validate_fingerprint(disk, expected, allow_unknown=False):
    ranges = [(s["offset"], s["length"]) for s in expected["samples"]]
    unknown = any(s["sha256"] is None for s in expected["samples"])
    if unknown and not allow_unknown:
        raise SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "source samples were unreadable; resume/mutation blocked")
    actual = fingerprint(disk, ranges, full=expected.get("full_sha256") is not None,
                         tolerate_errors=unknown)
    if actual != expected:
        raise SafetyError("BLOCKED_SOURCE_CHANGED", "source fingerprint changed")
    return actual


def masked_bytes(data, off, patches):
    b = bytearray(data)
    for p in patches:
        lo = max(off, p["offset"])
        hi = min(off + len(b), p["offset"] + p["length"])
        if hi > lo:
            b[lo - off:hi - off] = bytes(hi - lo)
    return bytes(b)


def controlled_write(disk, offset, data):
    disk._write_authorized = True
    try:
        return disk.write_at(offset, data)
    finally:
        disk._write_authorized = False


@contextlib.contextmanager
def source_lock(disk):
    """Hold image source control across verification; physical disks use offline control."""
    if disk.is_device:
        yield
        return
    fd = disk.fh.fileno()
    if os.name == "nt":
        import msvcrt
        class Overlapped(ctypes.Structure):
            _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                        ("Offset", ctypes.c_uint32), ("OffsetHigh", ctypes.c_uint32),
                        ("hEvent", ctypes.c_void_p)]
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.LockFileEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                 ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(Overlapped)]
        k.UnlockFileEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.c_uint32, ctypes.POINTER(Overlapped)]
        handle = ctypes.c_void_p(msvcrt.get_osfhandle(fd))
        ov = Overlapped()
        if not k.LockFileEx(handle, 3, 0, 0xffffffff, 0xffffffff, ctypes.byref(ov)):
            raise SafetyError("BLOCKED", "exclusive image control unavailable")
        try:
            yield
        finally:
            if not k.UnlockFileEx(handle, 0, 0xffffffff, 0xffffffff, ctypes.byref(ov)):
                raise SafetyError("FAILED_STATE_RESTORE", "image lock release failed")
    else:
        import fcntl
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise SafetyError("BLOCKED", "exclusive image control unavailable") from e
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def transaction_lock(directory):
    """OS lock releases on process death, retaining an inspectable lock file."""
    path = os.path.join(directory, "lock")
    with open(path, "a+b", buffering=0) as f:
        if os.fstat(f.fileno()).st_size == 0:
            f.write(b"0")
            os.fsync(f.fileno())
        f.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as e:
                raise SafetyError("BLOCKED", "transaction is in use") from e
        else:
            import fcntl
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                raise SafetyError("BLOCKED", "transaction is in use") from e
        try:
            yield
        finally:
            if os.name == "nt":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


class Transaction:
    def __init__(self, disk, action, patches, root, source, provenance,
                 structural, semantic=None, write_class="BLOCKED", guard=None,
                 fault=None):
        self.disk, self.action, self.patches = disk, action, patches
        self.root = os.path.abspath(root)
        self.source = source
        self.provenance = provenance
        self.structural, self.semantic = structural, semantic
        self.write_class, self.guard = write_class, guard
        self.fault = fault or (lambda point: None)
        self.transaction_id = str(uuid.uuid4())
        self.directory = os.path.join(self.root, self.transaction_id)
        self.path = os.path.join(self.directory, "transaction.json")
        self.state = "PLANNED"
        self.manifest = None
        self.events = []

    def event(self, state, patch=None, **metadata):
        p = patch or {}
        doc = {"event_index": len(self.events), "transaction_id": self.transaction_id,
               "timestamp": timestamp(), "state": state,
               "previous_event_sha256": (self.events[-1]["event_sha256"] if self.events
                                          else digest(canonical(self.manifest))),
               "source_fingerprint": self.source, "action": self.action,
               "offset": p.get("offset"), "length": p.get("length"),
               "metadata": metadata}
        doc["event_sha256"] = digest(canonical(doc))
        path = os.path.join(self.directory, "events", "%04d_%s.json" % (len(self.events), state))
        durable_json(path, doc)
        self.events.append(doc)
        self.state = state

    def begin(self):
        if self.write_class not in ELIGIBLE or not self.provenance or not callable(self.structural):
            raise SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "mandatory write oracle/provenance missing")
        if not callable(self.guard):
            raise SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "write guard missing")
        self.guard()
        validate_fingerprint(self.disk, self.source)
        specs, original, planned = [], bytearray(), bytearray()
        for p in self.patches:
            if p.offset < 0 or not p.new or p.offset + len(p.new) > self.disk.size:
                raise SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "patch out of bounds")
            if self.disk.base % self.disk.sector or p.offset % self.disk.sector or len(p.new) % self.disk.sector:
                raise SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "backup must cover every physically overwritten sector")
            if any(max(p.offset, q["offset"]) < min(p.offset + len(p.new), q["offset"] + q["length"])
                   for q in specs):
                raise SafetyError("BLOCKED_AMBIGUOUS", "overlapping patches")
            current = self.disk.read_at(p.offset, len(p.new))
            if p.old is None or len(current) != len(p.new) or current != p.old:
                raise SafetyError("BLOCKED_SOURCE_CHANGED", "patch precondition mismatch")
            specs.append({"offset": p.offset, "length": len(p.new), "label": p.label,
                          "artifact_offset": len(original), "sha256_before": digest(current),
                          "sha256_planned": digest(p.new), "state": "INFERRED" if
                          self.write_class == "OPERATOR_SUPPLIED_RECONSTRUCTION" else "VERIFIED",
                          "evidence_provenance": self.provenance,
                          "verification_oracle": self.action,
                          "rollback_artifact": "original.bin"})
            original.extend(current)
            planned.extend(p.new)
        if not specs:
            raise SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "empty plan")
        masked = []
        for s in self.source["samples"]:
            data = self.disk.read_at(s["offset"], s["length"])
            masked.append(dict(s, sha256=digest(masked_bytes(data, s["offset"], specs))))
        self.manifest = {"schema": 2, "transaction_id": self.transaction_id,
                         "timestamp": timestamp(), "action": self.action,
                         "source_fingerprint": self.source, "write_class": self.write_class,
                         "patches": specs, "original_sha256": digest(original),
                         "planned_sha256": digest(planned), "artifact_length": len(original),
                         "masked_samples": masked, "provenance": self.provenance,
                         "artifact_directory": self.directory,
                         "semantic_required": self.semantic is not None,
                         "environment": {"python": platform.python_version(), "os": platform.platform()}}
        os.makedirs(self.root, exist_ok=True)
        os.mkdir(self.directory)  # never reuse a directory, even after a crash
        sync_dir(self.root)
        os.mkdir(os.path.join(self.directory, "events"))
        sync_dir(self.directory)
        stage = "FAILED_JOURNAL"
        try:
            durable_json(self.path, self.manifest)
            self.event("PLANNED")
            stage = "FAILED_BACKUP"
            self.fault("before_backup")
            durable_create(os.path.join(self.directory, "original.bin"), bytes(original))
            self.event("BACKUP_CREATED")
            self.fault("after_backup_creation")
            self.fault("after_backup_fsync")
            durable_create(os.path.join(self.directory, "planned.bin"), bytes(planned))
            stage = "FAILED_BACKUP_VERIFY"
            self.validate_artifacts()
            self.event("BACKUP_HASH_VERIFIED")
            stage = "FAILED_JOURNAL"
            self.event("JOURNAL_PREPARED")
            self.fault("after_journal_prepared")
            return self.transaction_id
        except Exception as e:
            if self.events:
                self.event(getattr(e, "state", stage), error=str(e))
            raise

    def validate_artifacts(self):
        for name, key in (("original.bin", "original_sha256"), ("planned.bin", "planned_sha256")):
            path = os.path.join(self.directory, name)
            if os.path.getsize(path) != self.manifest["artifact_length"] or file_hash(path) != self.manifest[key]:
                raise SafetyError("FAILED_BACKUP_VERIFY", name)

    def run(self, force=False):
        with source_lock(self.disk):
            return self._run_locked(force)

    def _run_locked(self, force=False):
        # Kept as a compatibility argument only. It never affects authorization.
        with transaction_lock(self.directory):
            inspect_transaction(self.root, self.transaction_id)
            if self.state != "JOURNAL_PREPARED":
                raise SafetyError("FAILED_PREWRITE", "not prepared; writes cannot be resumed")
            self.guard()
            validate_fingerprint(self.disk, self.source)
            self.validate_artifacts()
            written = 0
            stage, mutation = "FAILED_PREWRITE", False
            readbacks = bytearray()
            try:
                for p, spec in zip(self.patches, self.manifest["patches"]):
                    self.guard()
                    current = self.disk.read_at(spec["offset"], spec["length"])
                    if digest(current) != spec["sha256_before"] or current != p.old:
                        raise SafetyError("BLOCKED_SOURCE_CHANGED", "current bytes differ")
                    self.fault("immediately_before_write")
                    self.event("WRITE_STARTED", spec)
                    stage, mutation = "FAILED_WRITE", True
                    if digest(p.new) != spec["sha256_planned"]:
                        raise SafetyError("FAILED_JOURNAL", "in-memory plan changed")
                    controlled_write(self.disk, spec["offset"], p.new)
                    self.fault("immediately_after_write")
                    self.event("WRITE_COMPLETED", spec)
                    stage = "FAILED_READBACK"
                    self.fault("before_readback")
                    data = self.disk.read_at(spec["offset"], spec["length"])
                    readback_name = "readback_%04d.bin" % spec['artifact_offset']
                    durable_create(os.path.join(self.directory, readback_name), data)
                    if len(data) != spec["length"] or digest(data) != spec["sha256_planned"] or data != p.new:
                        raise SafetyError("FAILED_READBACK", "exact byte verification failed")
                    readbacks.extend(data)
                    self.event("READBACK_VERIFIED", spec, sha256=digest(data), artifact=readback_name)
                    p.status = "done"
                    written += spec["length"]
                    self.fault("after_readback")
                durable_create(os.path.join(self.directory, "readback.bin"), bytes(readbacks))
                stage = "FAILED_STRUCTURAL_VERIFY"
                self.fault("before_structural_verify")
                self.fault("during_structural_verify")
                structural = self.structural(self.disk)
                if not isinstance(structural, dict) or structural.get("state") != "VERIFIED":
                    raise SafetyError(stage, str(structural))
                self.event("STRUCTURAL_VERIFIED", result=structural)
                stage = "FAILED_SEMANTIC_VERIFY"
                semantic = self.semantic(self.disk) if self.semantic else {
                    "state": "UNKNOWN", "reason": "no independent semantic oracle available"}
                if self.semantic and (not isinstance(semantic, dict) or semantic.get("state") != "VERIFIED"):
                    raise SafetyError(stage, str(semantic))
                if self.semantic:
                    self.event("SEMANTIC_VERIFIED", result=semantic)
                verification = {"structural": structural, "semantic": semantic,
                                "verdict": "RECOVERED_VERIFIED" if self.semantic else "RECOVERY_PARTIAL"}
                durable_json(os.path.join(self.directory, "verification.json"), verification)
                self.validate_artifacts()
                # Detect concurrent changes to untouched sampled regions too.
                validate_rollback_source(self.disk, self.manifest)
                self.fault("before_commit")
                self.event("COMMITTED", verification_sha256=digest(canonical(verification)),
                           verdict=verification["verdict"])
                return written
            except Exception as e:
                state = getattr(e, "state", stage)
                self.event(state, error=str(e))
                if mutation:
                    self.event("ROLLBACK_REQUIRED", failure=state)
                raise


def transaction_directory(root, transaction_id):
    try:
        if str(uuid.UUID(transaction_id)) != transaction_id:
            raise ValueError()
    except (ValueError, AttributeError):
        raise SafetyError("BLOCKED", "use a canonical transaction UUID, not a journal path")
    root = os.path.realpath(root)
    directory = os.path.realpath(os.path.join(root, transaction_id))
    if os.path.dirname(directory) != root:
        raise SafetyError("BLOCKED", "transaction escapes state root")
    return directory


def inspect_transaction(root, transaction_id):
    directory = transaction_directory(root, transaction_id)
    manifest = read_json(os.path.join(directory, "transaction.json"))
    if manifest.get("transaction_id") != transaction_id or manifest.get("schema") != 2:
        raise SafetyError("FAILED_JOURNAL", "manifest identity")
    prev, events = digest(canonical(manifest)), []
    for name in sorted(os.listdir(os.path.join(directory, "events"))):
        if not name.endswith(".json"):
            continue
        e = read_json(os.path.join(directory, "events", name))
        stored = e.get("event_sha256")
        hashed = {k: v for k, v in e.items() if k != "event_sha256"}
        expected_name = "%04d_%s.json" % (len(events), e.get("state"))
        if (name != expected_name or e.get("event_index") != len(events) or
                e.get("transaction_id") != transaction_id or
                e.get("previous_event_sha256") != prev or digest(canonical(hashed)) != stored or
                e.get("source_fingerprint") != manifest["source_fingerprint"]):
            raise SafetyError("FAILED_JOURNAL", "event chain tampered or incomplete")
        events.append(e)
        prev = stored
    if not events:
        raise SafetyError("FAILED_JOURNAL", "no durable events; no write authorized")
    for name, key in (("original.bin", "original_sha256"), ("planned.bin", "planned_sha256")):
        path = os.path.join(directory, name)
        if any(e["state"] == "BACKUP_HASH_VERIFIED" for e in events):
            if os.path.getsize(path) != manifest["artifact_length"] or file_hash(path) != manifest[key]:
                raise SafetyError("FAILED_BACKUP_VERIFY", name)
    if any(e["state"] == "COMMITTED" for e in events):
        commit = next(e for e in events if e["state"] == "COMMITTED")
        v = read_json(os.path.join(directory, "verification.json"))
        if digest(canonical(v)) != commit["metadata"]["verification_sha256"]:
            raise SafetyError("FAILED_JOURNAL", "verification tampered")
        if not any(e["state"] == "STRUCTURAL_VERIFIED" for e in events):
            raise SafetyError("FAILED_JOURNAL", "commit lacks structural verification")
        if manifest["semantic_required"] and not any(e["state"] == "SEMANTIC_VERIFIED" for e in events):
            raise SafetyError("FAILED_JOURNAL", "commit lacks semantic verification")
        combined = os.path.join(directory, 'readback.bin')
        if os.path.getsize(combined) != manifest['artifact_length'] or file_hash(combined) != manifest['planned_sha256']:
            raise SafetyError('FAILED_READBACK', 'combined readback artifact changed')
    for e in events:
        if e['state'] == 'READBACK_VERIFIED':
            artifact = e['metadata']['artifact']
            if os.path.basename(artifact) != artifact:
                raise SafetyError('FAILED_JOURNAL', 'invalid readback artifact path')
            path = os.path.join(directory, artifact)
            if os.path.getsize(path) != e['length'] or file_hash(path) != e['metadata']['sha256']:
                raise SafetyError('FAILED_READBACK', 'persisted readback artifact changed')
    state = events[-1]["state"]
    return {"manifest": manifest, "events": events, "state": state,
            "interrupted": state not in ("COMMITTED", "ROLLED_BACK_VERIFIED", "FAILED_PREWRITE"),
            "transaction_id": transaction_id}


def validate_rollback_source(disk, manifest):
    if identity(disk) != manifest["source_fingerprint"]["identity"]:
        raise SafetyError("ROLLBACK_SOURCE_STATE_CHANGED", "target identity mismatch")
    for s in manifest["masked_samples"]:
        data = disk.read_at(s["offset"], s["length"])
        if len(data) != s["length"] or digest(masked_bytes(data, s["offset"], manifest["patches"])) != s["sha256"]:
            raise SafetyError("ROLLBACK_SOURCE_STATE_CHANGED", "untouched source sample changed")
    expected_full = manifest["source_fingerprint"].get("full_sha256")
    if expected_full:
        with open(os.path.join(manifest["artifact_directory"], "original.bin"), "rb") as f:
            original = f.read()
        h, pos = hashlib.sha256(), 0
        while pos < disk.size:
            n = min(8 * 1024 * 1024, disk.size - pos)
            data = bytearray(disk.read_at(pos, n))
            if len(data) != n:
                raise SafetyError("ROLLBACK_SOURCE_STATE_CHANGED", "short full hash read")
            for p in manifest["patches"]:
                lo, hi = max(pos, p["offset"]), min(pos+n, p["offset"]+p["length"])
                if hi > lo:
                    start = p["artifact_offset"] + lo - p["offset"]
                    data[lo-pos:hi-pos] = original[start:start+hi-lo]
            h.update(data)
            pos += n
        if h.hexdigest() != expected_full:
            raise SafetyError("ROLLBACK_SOURCE_STATE_CHANGED", "full normalized source hash changed")


def rollback(root, transaction_id, opener, guard_factory, fault=None):
    directory = transaction_directory(root, transaction_id)
    fault = fault or (lambda point: None)
    with transaction_lock(directory):
        inspected = inspect_transaction(root, transaction_id)
        m = inspected["manifest"]
        if not any(e["state"] == "WRITE_STARTED" for e in inspected["events"]):
            raise SafetyError("BLOCKED", "transaction never authorized a write")
        tx = Transaction.__new__(Transaction)
        tx.directory, tx.manifest, tx.events = directory, m, inspected["events"]
        tx.source, tx.action, tx.transaction_id = m["source_fingerprint"], m["action"], transaction_id
        tx.state = inspected["state"]
        ident = tx.source["identity"]
        with opener(ident["canonical_path"], ident["sector_size"], ident["base_offset"]) as disk:
            try:
                validate_rollback_source(disk, m)
                with open(os.path.join(directory, "original.bin"), "rb") as f:
                    original = f.read()
                with open(os.path.join(directory, "planned.bin"), "rb") as f:
                    planned = f.read()
                # Preflight every patch before any rollback mutation.
                current_parts = []
                for p in m["patches"]:
                    a, n = p["artifact_offset"], p["length"]
                    old, new = original[a:a+n], planned[a:a+n]
                    if digest(old) != p["sha256_before"] or digest(new) != p["sha256_planned"]:
                        raise SafetyError("FAILED_BACKUP_VERIFY", "patch artifact mismatch")
                    cur = disk.read_at(p["offset"], n)
                    if cur not in (old, new):
                        raise SafetyError("ROLLBACK_SOURCE_STATE_CHANGED", "unexpected current bytes")
                    current_parts.append((p, old, new))
                tx.event("ROLLBACK_PLANNED")
                restored = 0
                with guard_factory(disk) as guard:
                    guard()
                    disk.reopen(writable=True)
                    with source_lock(disk):
                        validate_rollback_source(disk, m)
                        for p, old, new in reversed(current_parts):
                            guard()
                            cur = disk.read_at(p["offset"], p["length"])
                            if cur not in (old, new):
                                raise SafetyError("ROLLBACK_SOURCE_STATE_CHANGED", "bytes changed after preflight")
                            if cur != old:
                                tx.event("ROLLBACK_WRITE_STARTED", p)
                                fault("during_rollback")
                                controlled_write(disk, p["offset"], old)
                                tx.event("ROLLBACK_WRITE_COMPLETED", p)
                                restored += len(old)
                            if disk.read_at(p["offset"], p["length"]) != old:
                                raise SafetyError("FAILED_READBACK", "rollback readback mismatch")
                            tx.event("ROLLBACK_READBACK_VERIFIED", p, sha256=digest(old))
                        # Exact originals are the rollback oracle, not reconstruction.
                        validate_rollback_source(disk, m)
                        tx.event("ROLLED_BACK")
                        tx.event("ROLLED_BACK_VERIFIED")
                return restored
            except Exception as e:
                tx.event(getattr(e, "state", "ROLLBACK_REQUIRED"), error=str(e))
                raise
