"""Safety adapters and independent post-write oracles for the legacy engine."""
import contextlib
import ctypes
import json
import os
import re
import shutil
import struct
import uuid

import diskdoctor_core as core


def windows_state(dd, disk):
    index = dd.win_disk_index_from_path(disk.path)
    if index is None:
        raise core.SafetyError("BLOCKED_UNSUPPORTED_LAYOUT", "not a PhysicalDrive")
    rc, so, se = dd.ps(
        "$d=Get-Disk -Number %d -ErrorAction Stop; "
        "$p=@(Get-Partition -DiskNumber %d -ErrorAction Stop); "
        "$critical=@(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop | "
        "ForEach-Object {$_.Name.Substring(0,1)}); "
        "[pscustomobject]@{Disk=($d | Select-Object Number,Size,LogicalSectorSize,"
        "PhysicalSectorSize,SerialNumber,UniqueId,PartitionStyle,BusType,IsOffline,"
        "IsReadOnly,IsBoot,IsSystem); Volumes=@($p | Select-Object PartitionNumber,"
        "DriveLetter,IsBoot,IsSystem,AccessPaths); CriticalLetters=$critical} | "
        "ConvertTo-Json -Depth 8 -Compress" % (index, index))
    if rc != 0:
        raise core.SafetyError("BLOCKED_UNSUPPORTED_LAYOUT", "disk state query failed: " + se)
    try:
        doc = json.loads(so)
        d = doc["Disk"]
        required = ("Number", "Size", "LogicalSectorSize", "PhysicalSectorSize",
                    "UniqueId", "IsOffline", "IsReadOnly", "IsBoot", "IsSystem")
        if any(d.get(k) is None for k in required) or not d["UniqueId"]:
            raise ValueError("incomplete disk identity")
        if d["Number"] != index or d["Size"] != disk.size + disk.base:
            raise ValueError("device geometry identity differs")
        return doc
    except (ValueError, KeyError, TypeError) as e:
        raise core.SafetyError("BLOCKED_UNSUPPORTED_LAYOUT", str(e))


def stable_device_identity(dd, disk):
    if dd.IS_WIN:
        d = windows_state(dd, disk)["Disk"]
        # Operational flags are captured separately; intentional control changes
        # must not masquerade as replacement of the physical object.
        return {k: d[k] for k in ("Number", "Size", "LogicalSectorSize",
                                  "PhysicalSectorSize", "SerialNumber", "UniqueId", "BusType")}
    st = os.stat(disk.path)
    sysdev = os.path.realpath("/sys/dev/block/%d:%d" % (os.major(st.st_rdev), os.minor(st.st_rdev)))
    if not os.path.isdir(sysdev):
        raise core.SafetyError("BLOCKED_UNSUPPORTED_LAYOUT", "Linux device identity unavailable")
    data = {"sysfs_path": sysdev, "major": os.major(st.st_rdev), "minor": os.minor(st.st_rdev)}
    for name in ("device/serial", "device/wwid", "wwid", "queue/physical_block_size"):
        path = os.path.join(sysdev, name)
        if os.path.isfile(path):
            with open(path) as f:
                data[name] = f.read().strip()
    return data


def attach_identity(dd, disk):
    if disk.is_device:
        disk.identity_provider = lambda: stable_device_identity(dd, disk)


def absolute_guard(dd, disk):
    if not disk.is_device:
        return
    if not dd.is_admin():
        raise core.SafetyError("BLOCKED", "administrator/root required")
    if dd.IS_WIN:
        state = windows_state(dd, disk)
        d = state["Disk"]
        critical = set(state.get("CriticalLetters") or [])
        if d["IsSystem"] or d["IsBoot"] or any(
                v.get("IsSystem") or v.get("IsBoot") or v.get("DriveLetter") in critical
                for v in state["Volumes"]):
            raise core.SafetyError("BLOCKED_SYSTEM_DISK")
    else:
        # A complete mount/DM/MD/swap ancestry and exclusive-control proof has
        # not been implemented. Read-only analysis/imaging remain supported.
        raise core.SafetyError("BLOCKED_UNSUPPORTED_LAYOUT", "Linux raw device writes disabled; use an image")


class DiskControl:
    def __init__(self, dd, disk, events=None):
        self.dd, self.disk, self.events = dd, disk, events
        self.original = None

    def __enter__(self):
        absolute_guard(self.dd, self.disk)
        if self.disk.is_device:
            self.original = windows_state(self.dd, self.disk)
            try:
                d = self.original["Disk"]
                if d["IsReadOnly"] and not self.dd.win_set_readonly(d["Number"], False):
                    raise core.SafetyError("BLOCKED_OFFLINE_FAILURE", "could not clear read-only")
                if not d["IsOffline"] and not self.dd.win_set_offline(d["Number"], True):
                    raise core.SafetyError("BLOCKED_OFFLINE_FAILURE", "offline command failed")
                self.check()
            except BaseException:
                self.restore()
                raise
        return self.check

    def check(self):
        absolute_guard(self.dd, self.disk)
        if self.original:
            state = windows_state(self.dd, self.disk)
            old, new = self.original["Disk"], state["Disk"]
            if any(old[k] != new[k] for k in ("Number", "Size", "UniqueId", "SerialNumber")):
                raise core.SafetyError("BLOCKED_SOURCE_CHANGED", "disk control identity changed")
            if not new["IsOffline"] or new["IsReadOnly"]:
                raise core.SafetyError("BLOCKED_OFFLINE_FAILURE", "independent state confirmation failed")

    def restore(self):
        if self.original:
            d = self.original["Disk"]
            self.disk.close()
            # Verify identity before issuing any state command to this disk number.
            now = windows_state(self.dd, self.disk)["Disk"]
            if any(d[k] != now[k] for k in ("Number", "Size", "UniqueId", "SerialNumber")):
                raise core.SafetyError("FAILED_STATE_RESTORE", "disk identity changed")
            errors = []
            if bool(now["IsReadOnly"]) != bool(d["IsReadOnly"]):
                if not self.dd.win_set_readonly(d["Number"], bool(d["IsReadOnly"])):
                    errors.append("read-only restore failed")
            if bool(now["IsOffline"]) != bool(d["IsOffline"]):
                if not self.dd.win_set_offline(d["Number"], bool(d["IsOffline"])):
                    errors.append("offline restore failed")
            final = windows_state(self.dd, self.disk)["Disk"]
            if (final["IsOffline"], final["IsReadOnly"]) != (d["IsOffline"], d["IsReadOnly"]):
                errors.append("state restore verification failed")
            if errors:
                raise core.SafetyError("FAILED_STATE_RESTORE", "; ".join(errors))

    def __exit__(self, *exc):
        try:
            self.restore()
        except Exception as e:
            if self.events:
                self.events("FAILED_STATE_RESTORE", error=str(e))
            raise


def scan_fingerprint(dd, disk, result):
    regions = []
    for p in result.all_parts:
        if 0 <= p.start < disk.sectors and p.end < disk.sectors:
            n = min(dd.QUICK_PROBE_BYTES, p.sectors * disk.sector)
            regions.extend([(p.start * disk.sector, n), ((p.end + 1) * disk.sector - n, n)])
    for g in (result.gpt_p, result.gpt_b):
        if g and g.get("present"):
            regions.append((g["header_lba"] * disk.sector, disk.sector))
            length = len(g.get("entry_bytes", b""))
            off = (g.get("entry_lba") or 0) * disk.sector
            if length and off + length <= disk.size:
                regions.append((off, length))
    return core.fingerprint(disk, regions)


def classify(key):
    return {"gpt-restore-primary": "PROVEN_REDUNDANT_COPY",
            "gpt-restore-backup": "PROVEN_REDUNDANT_COPY",
            "gpt-fix-crc": "PROVEN_RECALCULATION",
            "gpt-fix-geometry": "OPERATOR_SUPPLIED_RECONSTRUCTION",
            "mbr-write-protective": "PROVEN_GEOMETRY_WITH_PRESERVED_IDENTITY",
            "mbr-rebuild": "INFERRED_GEOMETRY", "gpt-rebuild": "BLOCKED",
            "parttype-fix": "BLOCKED", "vbr-restore": "PROVEN_REDUNDANT_COPY",
            "vbr-restore-reverse": "PROVEN_REDUNDANT_COPY"}.get(key, "BLOCKED")


def redundant_conflicts(dd, result, key):
    a, b = result.gpt_p, result.gpt_b
    if a and b and a["valid"] and b["valid"]:
        if a["entry_bytes"] != b["entry_bytes"] or any(
                a["header"][k] != b["header"][k] for k in
                ("disk_guid", "first_usable", "last_usable", "entry_count", "entry_size")):
            raise dd.Blocked(key, "BLOCKED_AMBIGUOUS: both GPT copies are valid but disagree; historical recency is UNKNOWN")


def proven_crc(dd, result):
    for g, other in ((result.gpt_p, result.gpt_b), (result.gpt_b, result.gpt_p)):
        if not g or not g["present"] or g["valid"]:
            continue
        if not other or not other["valid"] or g["entry_bytes"] != other["entry_bytes"]:
            raise dd.Blocked("gpt-fix-crc", "BLOCKED_INSUFFICIENT_EVIDENCE: no matching valid redundant array")
        a, b = g["header"], other["header"]
        fields = ("disk_guid", "first_usable", "last_usable", "entry_count", "entry_size", "revision", "header_size")
        if any(a[k] != b[k] for k in fields) or a["current_lba"] != b["backup_lba"] or a["backup_lba"] != b["current_lba"]:
            raise dd.Blocked("gpt-fix-crc", "BLOCKED_CONFLICTING_EVIDENCE: header identity differs")


def geometry_provenance(dd, disk, result, args):
    size = getattr(args, "authoritative_size", None)
    provenance = getattr(args, "size_provenance", None)
    if not size or size != disk.size or not provenance or not provenance.strip():
        raise dd.Blocked("gpt-fix-geometry", "BLOCKED_INSUFFICIENT_EVIDENCE: independent size and provenance required")
    src = result.gpt_p if result.gpt_p["present"] else result.gpt_b
    if not src or not src["valid"]:
        raise dd.Blocked("gpt-fix-geometry", "BLOCKED_INSUFFICIENT_EVIDENCE: valid historical metadata required")


def verify_gpt(dd, disk):
    a, b = dd.read_gpt(disk, "primary"), dd.read_gpt(disk, "backup")
    checks = {}
    for side, g, my, alt in (("primary", a, 1, disk.sectors - 1),
                             ("backup", b, disk.sectors - 1, 1)):
        h = g.get("header") or {}
        checks[side + "_crc"] = bool(g["valid"])
        checks[side + "_header_size"] = 92 <= h.get("header_size", 0) <= disk.sector
        checks[side + "_reciprocal"] = h.get("current_lba") == my and h.get("backup_lba") == alt
        first, last = h.get("first_usable", 0), h.get("last_usable", 0)
        length = (h.get("entry_count", 0) * h.get("entry_size", 0) + disk.sector - 1) // disk.sector
        elba = h.get("entry_lba", 0)
        checks[side + "_usable"] = 2 <= first <= last < disk.sectors - 1
        checks[side + "_array_location"] = (2 <= elba and elba + length <= first if side == "primary"
                                                  else last < elba and elba + length <= my)
        entries = sorted(g["entries"], key=lambda e: e.first)
        checks[side + "_bounds"] = all(first <= e.first <= e.last <= last for e in entries)
        checks[side + "_no_overlap"] = all(x.last < y.first for x, y in zip(entries, entries[1:]))
        checks[side + "_identity"] = bool(h.get("disk_guid") and h["disk_guid"] != str(uuid.UUID(int=0))) and all(
            e.part_guid != str(uuid.UUID(int=0)) for e in entries)
        raw_entries = g.get('entry_bytes', b'')
        used_raw = []
        esz = h.get('entry_size', 0)
        if esz >= 128:
            used_raw = [dd.GptEntry(raw_entries[i:i+128], i // esz)
                        for i in range(0, len(raw_entries), esz)
                        if raw_entries[i:i+16] != dd.ZERO_GUID]
        checks[side + '_all_used_entries_valid'] = all(e.used and first <= e.first <= e.last <= last for e in used_raw)
        checks[side + '_unique_partition_guids'] = len({e.part_guid for e in used_raw}) == len(used_raw)
    checks["identical_arrays"] = a.get("entry_bytes") == b.get("entry_bytes")
    for k in ("disk_guid", "first_usable", "last_usable", "entry_count", "entry_size"):
        checks["matching_" + k] = (a.get("header") or {}).get(k) == (b.get("header") or {}).get(k)
    return {"state": "VERIFIED" if all(checks.values()) else "FAILED", "oracle": "independent GPT parse", "checks": checks}


def verify_mbr(dd, disk, expected, protective=False):
    m = dd.parse_mbr(disk)
    entries = sorted([e for e in m["entries"] if not e.empty], key=lambda e: e.start)
    checks = {"signature": m["signature_ok"], "no_overlap": all(x.end < y.start for x, y in zip(entries, entries[1:]))}
    if protective:
        checks["protective"] = m["protective_ok"] is True
        checks["single_entry"] = len(entries) == 1 and entries[0].type == 0xEE
    else:
        checks["bounds"] = all(0 < e.start <= e.end < disk.sectors for e in entries)
        checks["expected_extents"] = [(e.start, e.sectors) for e in entries] == [(p.start, p.sectors) for p in expected]
        checks["no_invented_boot"] = all(e.boot == 0 for e in entries)
        checks["filesystem_extent"] = all(p.ev and p.ev.extent_verified for p in expected)
    return {"state": "VERIFIED" if all(checks.values()) else "FAILED", "oracle": "MBR parse and independent extents", "checks": checks}


def verify_vbr(dd, disk, p, mirror):
    start = disk.read_lba(p.start, 12 if mirror["fs"] == "exFAT" else 1)
    backup = disk.read_lba(mirror["src_lba"], 12 if mirror["fs"] == "exFAT" else 1)
    fs = dd.probe_fs(start, disk.sector)
    checks = {"signature": fs is not None and fs["fs"] == mirror["fs"], "backup_equality": start == backup}
    if fs:
        fields = fs["fields"]
        if fs["fs"] == "NTFS":
            checks["bpb"] = dd.ntfs_fields_sane(fields)
            checks["extent"] = fields["total_sectors"] + 1 == p.sectors
        elif fs["fs"] == "FAT32":
            checks["bpb"] = dd.fat_fields_sane(fields) and dd._fat_geometry_ok(fields)
            checks["extent"] = 0 < fields["total_sectors"] <= p.sectors
        elif fs["fs"] == "exFAT":
            checks["checksums"] = dd.exfat_checksum_ok(disk, p.start, fields["bps"])[0] and dd.exfat_checksum_ok(disk, mirror["src_lba"], fields["bps"])[0]
            checks["extent"] = 0 < fields["volume_length"] <= p.sectors and fields["partition_offset"] == p.start
    return {"state": "VERIFIED" if all(checks.values()) else "FAILED", "oracle": "BPB/extent/backup parser", "checks": checks}


def ntfs_semantic(dd, disk, p):
    f = dd.ntfs_fields(disk.read_lba(p.start))
    cluster = f["bps"] * f["spc"]
    raw = disk.read_lba(p.start)
    code = struct.unpack_from("<b", raw, 0x40)[0]
    size = (1 << -code) if code < 0 else code * cluster
    if not (512 <= size <= 65536):
        return {"state": "FAILED", "reason": "invalid FILE record size"}

    def valid_record(off):
        data = disk.read_at(off, size)
        if len(data) != size or data[:4] != b"FILE":
            return None
        usa, count = struct.unpack_from("<HH", data, 4)
        if count != size // f["bps"] + 1 or usa < 8 or usa + 2 * count > size:
            return None
        usn = data[usa:usa+2]
        if not all(data[i * f['bps']-2:i * f['bps']] == usn for i in range(1, count)):
            return None
        decoded = bytearray(data)
        for i in range(1, count):
            decoded[i * f['bps']-2:i * f['bps']] = data[usa+2*i:usa+2*i+2]
        first_attr = struct.unpack_from('<H', decoded, 0x14)[0]
        used, allocated = struct.unpack_from('<II', decoded, 0x18)
        if not usa + count*2 <= first_attr < used <= allocated == size:
            return None
        attr, seen = first_attr, 0
        while attr + 4 <= used and seen < 256:
            kind = struct.unpack_from('<I', decoded, attr)[0]
            if kind == 0xffffffff:
                decoded[usa:usa+2] = b'\0\0'  # USA sequence itself is not semantic identity.
                return bytes(decoded)
            if attr + 24 > used:
                return None
            length = struct.unpack_from('<I', decoded, attr+4)[0]
            if kind == 0 or length < 24 or length % 8 or attr+length > used:
                return None
            attr += length
            seen += 1
        return None
    off = p.start * disk.sector + f["mft_lcn"] * cluster
    mirror_off = p.start * disk.sector + f["mftmirr_lcn"] * cluster
    limit = (p.end + 1) * disk.sector
    in_bounds = off >= p.start * disk.sector and off + 4 * size <= limit and mirror_off + size <= limit
    records = in_bounds and all(valid_record(off + i * size) is not None for i in range(4))
    mirror = in_bounds and valid_record(mirror_off) is not None
    if records and mirror:
        # $MFTMirr's first record must mirror the first $MFT record exactly.
        mirror = valid_record(off) == valid_record(mirror_off)
    return {"state": "VERIFIED" if records and mirror else "FAILED", "oracle": "NTFS FILE USA records and MFTMirr", "records_readable": bool(records), "mirror_relationship": bool(mirror)}


def bind_plan(dd, disk, result, args, act):
    if not result.source_fingerprint:
        raise core.SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "diagnosis has no source fingerprint")
    core.validate_fingerprint(disk, result.source_fingerprint)
    for p in act.patches:
        p.load_old(disk)
    logical = [{'offset': p.offset, 'length': len(p.new), 'label': p.label,
                'sha256_planned': core.digest(p.new)} for p in act.patches]
    # Journal all sectors touched by aligned RMW, including preserved bytes.
    if disk.base % disk.sector:
        raise core.SafetyError('BLOCKED_UNSUPPORTED_LAYOUT', 'unaligned source base is read-only')
    normalized = []
    for p in sorted(act.patches, key=lambda patch: patch.offset):
        first = p.offset // disk.sector * disk.sector
        last = (p.offset + len(p.new) + disk.sector - 1) // disk.sector * disk.sector
        if last > disk.size:
            raise core.SafetyError('BLOCKED', 'aligned patch extends outside source')
        old = disk.read_at(first, last-first)
        if old[p.offset-first:p.offset-first+len(p.new)] != p.old:
            raise core.SafetyError('BLOCKED_SOURCE_CHANGED', 'logical patch changed before normalization')
        new = bytearray(old)
        new[p.offset-first:p.offset-first+len(p.new)] = p.new
        if normalized and first < normalized[-1].offset + len(normalized[-1].new):
            raise core.SafetyError('BLOCKED_AMBIGUOUS', 'patches share physical sectors')
        normalized.append(dd.Patch(first, bytes(new), p.label, old))
    act.patches = normalized
    regions = [(s["offset"], s["length"]) for s in result.source_fingerprint["samples"]]
    regions += [(p.offset, len(p.new)) for p in act.patches]
    act.source_fingerprint = core.fingerprint(disk, regions, full=getattr(args, 'source_sha256', False))
    act.provenance = {"run_id": result.run_id, "diagnosis": result.to_dict(), "notes": act.notes,
                      "action": act.key, "write_class": act.write_class,
                      "logical_patches": logical}
    if act.key == "gpt-fix-geometry":
        act.provenance["size_oracle"] = {"state": "OPERATOR_SUPPLIED", "bytes": args.authoritative_size, "provenance": args.size_provenance}
    if act.key.startswith("gpt-"):
        act.structural_oracle = lambda d: verify_gpt(dd, d)
    elif act.key == "mbr-write-protective":
        act.structural_oracle = lambda d: verify_mbr(dd, d, [], protective=True)
    elif act.key.startswith("vbr-"):
        p = dd._find_part(result, args.part)
        mirror = dd.find_validated_mirror(disk, p)
        if p.fs and p.ev and p.ev.signals.get('bpb_consistency', {}).get('value') and not dd.bpb_match(
                mirror['fs'], p.fs['fields'], dd.probe_fs(disk.read_lba(mirror['src_lba']), disk.sector)['fields'])[0]:
            raise core.SafetyError('BLOCKED_CONFLICTING_EVIDENCE', 'primary and backup BPBs disagree')
        if mirror['fs'] == 'FAT32':
            # The legacy diagnostic finder retains its first-hit behavior;
            # the writer independently rejects competing valid backup BPBs.
            for delta in (1, 6, 12):
                sector = disk.read_lba(p.start + delta)
                if not dd._looks_like_fat32(sector):
                    continue
                f = dd.fat_fields(sector, 32)
                if (dd.fat_fields_sane(f) and dd._fat_geometry_ok(f) and
                        f['bk_boot_sec'] == delta and 0 < f['total_sectors'] <= p.sectors and
                        delta + p.start != mirror['src_lba']):
                    raise core.SafetyError('BLOCKED_AMBIGUOUS', 'multiple valid FAT32 backup positions')
        act.structural_oracle = lambda d: verify_vbr(dd, d, p, mirror)
        if mirror["fs"] == "NTFS":
            act.semantic_oracle = lambda d: ntfs_semantic(dd, d, p)
    else:
        raise core.SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "no independent structural oracle")
    class PlannedView:
        def __getattr__(self, name):
            return getattr(disk, name)
        def read_at(self, off, length):
            data = bytearray(disk.read_at(off, length))
            for patch in act.patches:
                lo, hi = max(off, patch.offset), min(off+len(data), patch.offset+len(patch.new))
                if hi > lo:
                    data[lo-off:hi-off] = patch.new[lo-patch.offset:hi-patch.offset]
            return bytes(data)
        def read_lba(self, lba, count=1):
            return self.read_at(lba * disk.sector, count * disk.sector)
    view = PlannedView()
    prospective = act.structural_oracle(view)
    if prospective.get('state') != 'VERIFIED':
        raise core.SafetyError('BLOCKED_INSUFFICIENT_EVIDENCE', 'planned bytes fail independent structural oracle: ' + str(prospective))
    act.provenance['prospective_structural'] = prospective
    if act.semantic_oracle:
        prospective_semantic = act.semantic_oracle(view)
        if prospective_semantic.get('state') != 'VERIFIED':
            raise core.SafetyError('BLOCKED_INSUFFICIENT_EVIDENCE', 'independent semantic preflight failed: ' + str(prospective_semantic))
        act.provenance['prospective_semantic'] = prospective_semantic


def execute(dd, disk, result, args, key):
    if key in dd.EXTERNAL_ACTIONS:
        return external(dd, disk, result, args, key)
    builder = dd.ACTION_BUILDERS.get(key)
    if not builder:
        dd.err("unknown action: " + key)
        return dd.EXIT_ARG
    tx = None
    try:
        act = builder(disk, result, args)
        absolute_guard(dd, disk) if args.apply else None
        exempt = dd.BLOCKER_EXEMPT.get(key, ())
        active = [(k, why) for k, why in result.blockers if k not in exempt]
        if active:
            raise core.SafetyError("BLOCKED_CONFLICTING_EVIDENCE", str(active))
        if act.write_class in core.ELIGIBLE:
            bind_plan(dd, disk, result, args, act)
        dd.out("WRITE CLASS: " + act.write_class)
        dd.preview_patches(disk, act.patches)
        if not args.apply:
            dd.info("READ_ONLY_PREVIEW")
            return dd.EXIT_OK
        if act.write_class not in core.ELIGIBLE:
            raise core.SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "consent does not prove inferred geometry")
        if act.write_class == "OPERATOR_SUPPLIED_RECONSTRUCTION" and not args.allow_inferred:
            raise core.SafetyError("BLOCKED", "explicit --allow-inferred also required")
        if all(p.old == p.new for p in act.patches):
            dd.info("UNCHANGED: no write needed")
            return dd.EXIT_OK
        if not dd.confirm(assume_yes=args.yes):
            return dd.EXIT_CANCEL
        root = transaction_root(args)
        rejection_gate(root, act)
        ensure_destination(dd, disk, root)
        control = DiskControl(dd, disk)
        with control as guard:
            core.validate_fingerprint(disk, act.source_fingerprint)
            act.provenance["original_disk_state"] = control.original or {"kind": "image", "writable": False}
            tx = core.Transaction(disk, key, act.patches, root, act.source_fingerprint,
                                  act.provenance, act.structural_oracle, act.semantic_oracle,
                                  act.write_class, guard)
            tx.begin()
            result.transactions.append(tx.transaction_id)
            disk.reopen(writable=True)
            tx.run()
            dd.ok("TRANSACTION: " + tx.transaction_id)
            v = core.read_json(os.path.join(tx.directory, "verification.json"))
            dd.out(v["verdict"])
        # State restoration happens after raw verification, never before.
        disk.reopen(writable=False)
        return dd.EXIT_OK
    except dd.Blocked as e:
        dd.print_blocked(key, e.reasons)
        return dd.EXIT_BLOCKED
    except (core.SafetyError, dd.DiskError, OSError) as e:
        dd.err(str(e))
        if tx and tx.events:
            dd.err("TRANSACTION: " + tx.transaction_id + " STATE: " + tx.state)
            if getattr(e, "state", None) == "FAILED_STATE_RESTORE":
                tx.event("FAILED_STATE_RESTORE", error=str(e))
        return dd.EXIT_BLOCKED if getattr(e, "state", "").startswith("BLOCKED") else dd.EXIT_ERR
    finally:
        if disk.writable:
            disk.reopen(writable=False)


def transaction_root(args):
    return os.path.join(getattr(args, "state_dir", "DiskDoctor"), "transactions")


def rejection_gate(root, action):
    """Reject identical failed verification hypotheses; record material changes."""
    material = {'identity': action.source_fingerprint['identity'],
                'samples': action.source_fingerprint['samples'],
                'planned_sha256': core.digest(b''.join(p.new for p in action.patches)),
                'size_oracle': action.provenance.get('size_oracle'),
                'oracle_version': 'v2-rc1'}
    action.provenance['material_variables'] = material
    changed = []
    if os.path.isdir(root):
        for tid in sorted(os.listdir(root)):
            if not os.path.isdir(os.path.join(root, tid)):
                continue
            tx = core.inspect_transaction(root, tid)
            m = tx['manifest']
            if m['action'] != action.key or m['source_fingerprint']['identity'] != material['identity']:
                continue
            if not any(e['state'] in ('FAILED_STRUCTURAL_VERIFY', 'FAILED_SEMANTIC_VERIFY') for e in tx['events']):
                continue
            previous = m['provenance'].get('material_variables')
            if previous == material:
                raise core.SafetyError('BLOCKED', 'REJECTED hypothesis cannot be retried without a material change: ' + tid)
            changed.append({'rejected_transaction_id': tid,
                            'changed_variables': [key for key in material if (previous or {}).get(key) != material[key]]})
    action.provenance['prior_rejections'] = changed


def inspect(dd, args):
    doc = core.inspect_transaction(transaction_root(args), args.inspect)
    dd.out(json.dumps(doc, ensure_ascii=False, indent=2))


def undo(dd, args):
    def opener(path, sector, base):
        return dd.RawDisk(path, sector_size=sector, base_offset=base, writable=False)
    return core.rollback(transaction_root(args), args.undo, opener, lambda d: DiskControl(dd, d))


def volume_identity(path):
    if os.name != "nt":
        raise core.SafetyError("BLOCKED_UNSUPPORTED_LAYOUT", "Windows volume identity required")
    probe = os.path.abspath(path)
    while not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            raise core.SafetyError("BLOCKED", "destination volume cannot be resolved")
        probe = parent
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    mount = ctypes.create_unicode_buffer(32768)
    name = ctypes.create_unicode_buffer(32768)
    k.GetVolumePathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    k.GetVolumeNameForVolumeMountPointW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    if not k.GetVolumePathNameW(os.path.realpath(probe), mount, len(mount)) or not k.GetVolumeNameForVolumeMountPointW(mount.value, name, len(name)):
        raise core.SafetyError("BLOCKED", "volume identity lookup failed")
    return name.value.lower()


def ensure_destination(dd, disk, path):
    """Reject source aliases and physical source-volume destinations before creation."""
    canonical = os.path.normcase(os.path.realpath(path))
    source = os.path.normcase(os.path.realpath(disk.path))
    if canonical == source or (os.path.exists(path) and not disk.is_device and os.path.samefile(path, disk.path)):
        raise core.SafetyError("BLOCKED", "output aliases source object")
    if disk.is_device and dd.IS_WIN:
        destination = volume_identity(path)
        state = windows_state(dd, disk)
        for v in state["Volumes"]:
            paths = list(v.get("AccessPaths") or [])
            if v.get("DriveLetter"):
                paths.append(str(v["DriveLetter"]) + ":\\")
            for mount in paths:
                if destination == volume_identity(mount):
                    raise core.SafetyError("BLOCKED", "destination resides on source physical disk")


def protect_outputs(dd, args):
    """Run before opening a log/report, including when --auto ignores actions."""
    outputs = [getattr(args, key, None) for key in ('json', 'log', 'image_out', 'auto_out')]
    if getattr(args, 'auto_out', None):
        outputs.append(os.path.splitext(args.auto_out)[0] + '.json')
    if getattr(args, 'dump_range', None):
        outputs.append(args.dump_out)
    if getattr(args, 'carve_vbk', None):
        outputs.append(args.carve_out)
    if not getattr(args, 'disk', None):
        # For --auto --all, defer validation until enumeration, before opening files.
        return
    path = dd.resolve_target(args.disk)
    if path and os.path.exists(path):
        with dd.RawDisk(path, sector_size=args.sector_size, base_offset=args.offset) as disk:
            for output in outputs:
                if output:
                    ensure_destination(dd, disk, output)


def persist_report(dd, disk, result, args, triage=None, final=False):
    root = os.path.join(getattr(args, 'state_dir', 'DiskDoctor'), 'reports', result.run_id)
    ensure_destination(dd, disk, root)
    os.makedirs(root, exist_ok=True)
    doc = result.to_dict()
    doc['triage'] = triage
    plans = []
    for key, builder in dd.ACTION_BUILDERS.items():
        try:
            act = builder(disk, result, args)
            plans.append({'action': key, 'state': 'INFERRED' if act.write_class not in core.ELIGIBLE else 'HYPOTHESIS',
                          'write_class': act.write_class, 'source_fingerprint': result.source_fingerprint,
                          'patches': [{'offset': p.offset, 'length': len(p.new), 'sha256_planned': core.digest(p.new)} for p in act.patches],
                          'provenance': act.notes})
        except dd.Blocked as e:
            plans.append({'action': key, 'state': 'BLOCKED', 'reasons': e.reasons})
    doc['repair_plans'] = plans
    doc['verification_results'] = []
    for tid in result.transactions:
        tx = core.inspect_transaction(transaction_root(args), tid)
        doc['verification_results'].append({'transaction_id': tid, 'state': tx['state'],
                                             'events': tx['events']})
        if tx['state'] == 'COMMITTED':
            doc['final_verdict'] = tx['events'][-1]['metadata']['verdict']
        else:
            doc['final_verdict'] = tx['state']
    name = 'final' if final else 'analysis'
    core.durable_json(os.path.join(root, name + '.json'), doc)
    lines = ['DiskDoctor ' + dd.VERSION, 'RUN: ' + result.run_id,
             'SOURCE: ' + disk.path, 'IDENTITY: ' + doc['source_identity_state'],
             'SCHEME: ' + result.scheme, 'VERDICT: ' + doc['final_verdict'],
             'Fingerprint: ' + str((result.source_fingerprint or {}).get('sha256'))]
    lines += ['BLOCKER: ' + key + ': ' + why for key, why in result.blockers]
    lines += ['CANDIDATE: ' + json.dumps(p.to_dict(disk.sector), ensure_ascii=False) for p in result.all_parts]
    lines += ['PLAN: ' + json.dumps(p, ensure_ascii=False) for p in plans]
    core.durable_create(os.path.join(root, name + '.txt'), '\n'.join(lines).encode('utf-8'))
    return doc


def external(dd, disk, result, args, key):
    classification = {"chkdsk": "SOURCE_MUTATING_EXTERNAL", "refsutil": "DESTINATION_ONLY_RECOVERY",
                      "rescan": "READ_ONLY_EXTERNAL"}[key]
    dd.out("EXTERNAL CLASS: " + classification)
    if key == "rescan":
        # No metadata write, but changes OS presentation; never invoked by auto.
        return dd.EXIT_OK if dd.win_rescan() else dd.EXIT_ERR
    try:
        if not dd.IS_WIN or not args.letter or not re.fullmatch("[A-Za-z]:?", args.letter):
            raise core.SafetyError("BLOCKED", "explicit Windows drive letter required")
        letter = args.letter.rstrip(":").upper()
        index = dd.win_disk_index_from_path(disk.path)
        state = windows_state(dd, disk)
        if index is None or not any(str(v.get("DriveLetter", "")).upper() == letter for v in state["Volumes"]):
            raise core.SafetyError("BLOCKED_SOURCE_CHANGED", "letter does not belong to diagnosed disk")
        if not result.source_fingerprint:
            raise core.SafetyError("BLOCKED_INSUFFICIENT_EVIDENCE", "source fingerprint unavailable")
        core.validate_fingerprint(disk, result.source_fingerprint)
        if key == "chkdsk":
            dd.out("NON_TRANSACTIONAL_EXTERNAL_MUTATION: no byte rollback is promised")
            absolute_guard(dd, disk)
            if not args.apply or not getattr(args, "authorize_external_mutation", False):
                dd.info("PREVIEW: requires --apply --authorize-external-mutation")
                return dd.EXIT_OK
            cmd = ["chkdsk", letter + ":", "/f"]
        else:
            work = args.refs_work
            dest = args.refs_out
            if not work or not dest:
                raise core.SafetyError("BLOCKED", "explicit separate working/destination volumes required")
            source_volume = volume_identity(letter + ":\\")
            if source_volume in (volume_identity(work), volume_identity(dest)):
                raise core.SafetyError("BLOCKED", "working/destination aliases source volume")
            cmd = ["refsutil", "salvage", "-" + args.refs_mode, letter + ":", work, dest, "-x"]
        run_id = str(uuid.uuid4())
        root = os.path.join(getattr(args, "state_dir", "DiskDoctor"), "logs", run_id)
        ensure_destination(dd, disk, root)
        os.makedirs(root, exist_ok=False)
        exe = shutil.which(cmd[0])
        if not exe:
            raise core.SafetyError("BLOCKED", "external tool missing")
        cmd[0] = exe
        version_rc, version_text, _ = dd.ps("(Get-Item -LiteralPath '%s' -ErrorAction Stop).VersionInfo.FileVersion" % exe.replace("'", "''"))
        record = {"run_id": run_id, "classification": classification,
                  "rollback": "UNSUPPORTED" if key == "chkdsk" else "NOT_APPLICABLE",
                  "label": "NON_TRANSACTIONAL_EXTERNAL_MUTATION" if key == "chkdsk" else classification,
                  "executable": exe, "command_line": cmd, "target_volume": letter + ":",
                  "tool_version": version_text.strip() if version_rc == 0 and version_text.strip() else "UNKNOWN",
                  "source_fingerprint": result.source_fingerprint,
                  "pre_state": state, "timestamp": core.timestamp()}
        core.durable_json(os.path.join(root, "prepared.json"), record)
        core.validate_fingerprint(disk, result.source_fingerprint)
        if key == "refsutil":
            os.makedirs(work, exist_ok=True)
            os.makedirs(dest, exist_ok=True)
        rc, so, se = dd.run_cmd(cmd, timeout=7200)
        record.update(stdout=so, stderr=se, exit_code=rc, post_state=windows_state(dd, disk),
                      verification_result={"state": "UNKNOWN", "reason": "exit status is not semantic recovery proof"})
        core.durable_json(os.path.join(root, "result.json"), record)
        dd.out(so)
        dd.out(se)
        if key == "refsutil":
            mismatch = dd.parse_refsutil_version_mismatch(so + "\n" + se)
            if mismatch:
                dd.print_refsutil_version_mismatch(mismatch)
                return dd.EXIT_ERR
        return dd.EXIT_OK if rc == 0 else dd.EXIT_ERR
    except (core.SafetyError, OSError) as e:
        dd.err(str(e))
        return dd.EXIT_BLOCKED
