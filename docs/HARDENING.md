# DiskDoctor 2.0.0-rc1

This is a review candidate, not a final production release. The v1.9.5 tag and
main history are preserved. The forensic algorithms remain the reference engine;
write authorization, persistence, verification and rollback are separate modules.

## Decision and state model

Observation -> evidence -> candidates -> diagnosis -> unique byte plan -> gate ->
immutable original/planned artifacts -> durable event journal -> bounded sector
write -> mandatory sync -> exact persisted readback -> independent structural
verification -> available semantic verification -> commit.

`VERIFIED`, `REJECTED`, `INFERRED`, `HYPOTHESIS`, `UNKNOWN`, `PATCHED`, `REVERTED`,
`BLOCKED` and `FAILED` distinguish observations from inference. Legacy confidence
scores are retained as diagnostic scores; they never authorize a write themselves.
An operator's consent does not create evidence. Operator size provenance is
`OPERATOR_SUPPLIED`, never independently verified. Failed structural/semantic
hypotheses cannot be repeated unchanged; material variable changes are recorded.

`PROVEN_REDUNDANT_COPY`, `PROVEN_RECALCULATION` and
`PROVEN_GEOMETRY_WITH_PRESERVED_IDENTITY` require unique supporting bytes.
`OPERATOR_SUPPLIED_RECONSTRUCTION` additionally requires explicit authorization.
`INFERRED_GEOMETRY`, `AMBIGUOUS` and `BLOCKED` cannot be executed.

## Identity and controlled mutation

Image identity binds canonical path, filesystem device/inode, underlying file
size, view base/size/sector size, mtime, head/middle/tail samples and observed
structural regions. The opened handle must name the same object as the path.
Optional whole-source hashing is enabled with `--source-sha256`.

Physical Windows identity additionally includes disk number, serial, UniqueId,
logical/physical sector size and bus type. Disk/partition system, boot, pagefile,
offline/read-only and mounted-volume state is captured separately. Intentional
offline transitions do not invalidate stable device identity. Missing identity,
administrator rights or state-query evidence blocks a device mutation.

Source samples are not a full-image historical proof. Without full hashing,
changes outside samples and patch ranges cannot be excluded. Hashes prove byte
equality, not recency or historical correctness. Competing valid GPT copies are
ambiguous; neither is chosen automatically. Linux device identity remains
available for analysis; Linux raw device writes are deliberately blocked pending
complete mount/DM/MD/swap ancestry and exclusive-control verification.

`--force` is deprecated and ignored for all mutation authorization. System disk,
source identity/current-byte, evidence, ambiguity, offline, sync and verification
failures have no override. Direct `RawDisk.write_at` requires a transaction
capability. Image writes hold an OS file lock. POSIX locks are advisory; other
processes must honor them. Windows uses a full-file exclusive range lock.

Windows raw writes prove non-system status, capture original state, clear
read-only only when necessary, offline the disk and independently confirm that
state before writable reopen. Original flags are restored after raw verification,
including preserving an originally offline disk. State restoration failure is
explicitly `FAILED_STATE_RESTORE`; transaction commitment alone does not hide it.
Failure paths also restore original operational state. No mounted-volume write
fallback is used when offline fails.

## Immutable transaction storage

```
DiskDoctor/
  reports/<run_uuid>/analysis.json, analysis.txt, final.json, final.txt
  transactions/<transaction_uuid>/
    transaction.json
    original.bin
    planned.bin
    readback.bin
    readback_<offset_in_artifact>.bin
    verification.json
    events/0000_PLANNED.json, ...
    lock
  logs/<external_run_uuid>/prepared.json, result.json
```

Transaction directories use UUID4 and exclusive creation. Artifacts and events
are never replaced by the application. Every original/planned artifact is
flushed, synchronized, closed, reopened and verified against its full SHA-256.
Backups cover every sector physically touched by an aligned write, including
unchanged padding. Unaligned source views are analysis-only.

Each event binds index, UUID, UTC timestamp, state, source fingerprint, action,
offset/length, metadata and the previous full SHA-256. The first event binds the
immutable manifest. File sync and directory sync are required on POSIX; Windows
uses synced file contents and exclusive write-through publication. Storage
hardware must actually honor these durability operations. No power-loss test on
real hardware has been performed.

The application treats artifacts as immutable, but does not install filesystem
ACLs or a WORM store. Hash chains detect accidental/partial tampering relative to
the retained manifest; they are not signatures. An attacker controlling the
entire state tree could replace the tree and recompute hashes. Protect the state
directory using appropriate storage/access controls. This is not an adversarial
cryptographic audit log.

Successful states include `PLANNED`, `BACKUP_CREATED`, `BACKUP_HASH_VERIFIED`,
`JOURNAL_PREPARED`, `WRITE_STARTED`, `WRITE_COMPLETED`, `READBACK_VERIFIED`,
`STRUCTURAL_VERIFIED`, available `SEMANTIC_VERIFIED`, and `COMMITTED`.
Failures retain distinct journal states and `ROLLBACK_REQUIRED` after any write
may have started. The last durable event exposes interrupted transactions.
Source writes are never resumed automatically.

## Verification and supported actions

GPT copies are verified by parsing signatures, sizes, both CRCs, reciprocal
headers, usable bounds, entry-array positions, every nonempty entry, unique
partition GUIDs, no overlap and matching primary/backup identities and arrays.
CRC recalculation requires a valid matching redundant array and matching header
identity; plausible geometry alone is insufficient. Geometry adjustment requires
a valid historical table plus an independent authoritative byte size and recorded
provenance. Current device size alone cannot authorize adjustment.

MBR protective writes preserve disk signature/boot code and verify the protective
entry. A proposed MBR reconstruction does not invent an active flag. Inferred
MBR geometry remains preview-only. GPT reconstruction and partition type changes
are blocked when historical semantic identity cannot be proven; small FAT
partitions are never guessed to be ESPs. No new historical GUID/name/attribute is
invented by a repair action. The low-level `build_gpt` helper still generates
fresh tables for synthetic fixture creation, not authorized recovery.

NTFS/FAT32/exFAT VBR restores require validated backup geometry/relationships,
matching BPBs where a valid primary survives, and a unique supported candidate.
NTFS additionally requires readable FILE records with USA fixups, attribute
bounds and an MFTMirr relationship. FAT/exFAT verify BPBs, extent, backup bytes
and defined checksums. Prospective independent oracles run before any mutation;
they run again against actual disk bytes after writing. A higher score is not
an oracle. GPT/MBR OS recognition and complete FAT/exFAT semantic recovery are
currently `UNKNOWN`; commits without a semantic oracle report `RECOVERY_PARTIAL`,
not `RECOVERED_VERIFIED`.

ReFS diagnostics, tail-copy validation, entropy controls and refsutil version
mismatch interpretation are preserved. The authoritative v1.9.5 implementation
**did not perform a sector-level ReFS header restore**. V2 preserves that refusal.
Tail-header recovery remains diagnostic evidence; independent ReFS bootstrap
verification/write support is still unsupported. There is no claimed ReFS raw
restore regression that the baseline did not implement.

## Rollback

`--undo` accepts a canonical UUID resolved under the selected state directory.
Mutable v1 journals cannot authorize writes. Inspection validates the event
chain, manifest, artifacts and committed verification results. Rollback verifies
identity, untouched source samples (or normalized full source hash), offsets,
lengths and all current patch bytes against exactly the original or planned
bytes before any rollback write. Unknown/torn/unrelated bytes block rollback.

Rollback appends `ROLLBACK_PLANNED`, `ROLLBACK_WRITE_STARTED`,
`ROLLBACK_WRITE_COMPLETED`, `ROLLBACK_READBACK_VERIFIED`, `ROLLED_BACK` and
`ROLLED_BACK_VERIFIED`. It uses the same disk control, bounded write, sync and
exact readback. Already-restored patches are verified and skipped. An interrupted
rollback can be retried after validated preflight; success never means only that
write returned. Already rolled-back transactions still validate their source.

## External actions

`READ_ONLY_EXTERNAL`, `DESTINATION_ONLY_RECOVERY` and
`SOURCE_MUTATING_EXTERNAL` are separate from sector transactions. `chkdsk /f`
requires both `--apply` and `--authorize-external-mutation`, is labeled
`NON_TRANSACTIONAL_EXTERNAL_MUTATION`, and promises no byte rollback. Records
include executable/version where available, command, verified target letter,
fingerprint, pre/post state, output, exit code and verification outcome. Interrupted
external runs retain a prepared record; recovery remains `UNKNOWN` if no independent
semantic oracle exists. `refsutil` work/destination aliases are checked using
Windows volume identity before creating directories; its version mismatch is
parsed from the utility output, never relabeled as corruption.

## Imaging and search scope

Chunk retry, sector descent, explicit filler and exact bad ranges remain intact.
Every run has UUID, source identity, exclusively created output, chained durable
checkpoints, synced progress, stream hash, rate/elapsed/ETA, bad bytes/ranges and
final size. Optional reopened whole-image hashing uses `--image-sha256`.
Resume requires matching source/parameters/output identity and verified prefix
hash. Uncommitted trailing output bytes are truncated only after prefix validation.
Unreadable identity samples do not prevent a new forensic acquisition, but leave
identity evidence `UNKNOWN` and block resume. Existing outputs are never silently
overwritten. Completed imaging is idempotently inspectable.

Raw name/VBM searches report tested scope, processed bytes, completion and hit
caps. Limited/short/stopped searches cannot establish complete absence. Deep scans
also report tested scope/time limit. High entropy alone remains insufficient to
declare a compressed backup repository overwritten. VBK verification preserves
the field-tested selection among equally ranked neighboring candidates.

Auto mode ignores mutation options/actions and opens sources read-only. JSON,
logs, dumps, carving, images, transaction storage and auto reports are checked for
source aliases before creation. Windows physical destinations are checked against
the source's mounted volume identities.

## Commands

Run from the project directory; distribute all four runtime Python modules.

```powershell
# Read-only analysis and persistent reports
python diskdoctor.py --disk suspect.img --scan --explain --state-dir DiskDoctor
python diskdoctor.py --disk suspect.img --auto --auto-out analysis.txt

# Repair preview
python diskdoctor.py --disk suspect.img --action gpt-restore-primary

# Controlled sector repair, with full source identity checking
python diskdoctor.py --disk suspect.img --action gpt-restore-primary --apply --source-sha256

# Operator-supplied size oracle (must match the presented size)
python diskdoctor.py --disk suspect.img --action gpt-fix-geometry --authoritative-size 1073741824 --size-provenance "Acquisition record X" --apply --allow-inferred

# Inspect / rollback (replace the example with the printed transaction UUID)
python diskdoctor.py --inspect 00000000-0000-4000-8000-000000000000 --state-dir DiskDoctor
python diskdoctor.py --undo 00000000-0000-4000-8000-000000000000 --state-dir DiskDoctor
python diskdoctor.py --check-journals --state-dir DiskDoctor

# Image, resume and independently hash the final image
python diskdoctor.py --disk suspect.img --image-out acquired.img --image-sha256
python diskdoctor.py --disk suspect.img --image-out acquired.img --image-resume --image-sha256

# Synthetic tests only
python diskdoctor.py --self-test --lang en --no-color
python -m unittest discover -s tests -p "test_*.py" -v
```

## Remaining unsupported/UNKNOWN cases

Linux raw mutation; dynamic disks/Storage Spaces; ambiguous historical copies;
unproven GPT identity/role; unproven inferred MBR geometry; raw ReFS reconstruction;
unaligned writable image views; unknown/torn rollback bytes; automatic forward
transaction resume; hostile replacement of an entire state tree; full filesystem
semantic verification for GPT/MBR/FAT/exFAT; OS-level recognition while a Windows
disk is offline; hardware durability beyond reported sync success.

Tests use synthetic images and mocked Windows state only. A passing Windows CI
job does not certify real PhysicalDrive handling or storage power-loss behavior.
See [baseline](BASELINE.md), [mutation audit](MUTATION_AUDIT.md) and
[validation results](VALIDATION.md) before review or release.
