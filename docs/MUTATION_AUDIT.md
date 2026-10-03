# Complete mutation-path audit

Scope: all runtime Python modules, synthetic fixture helpers, reference fixture,
test suite and CI. Audited APIs: write/write_at/write_lba, truncate,
replace/rename/remove/unlink, Set-Disk, diskpart, chkdsk, refsutil, subprocess,
ctypes file/volume APIs. No source mutation is performed by auto mode.

| Path / API | Object modified | Transactional / reversible | Authorization and verification | Failure |
|---|---|---|---|---|
| `RawDisk.write_at` / `write_lba` | exact full sectors of source | v2 transaction only; exact backup rollback | capability, writable handle, bounds/full RMW read, exact write count, flush/fsync; caller exact readback and oracles | FAILED_WRITE / FAILED_DURABILITY / FAILED_READBACK |
| `core.controlled_write` | delegates source write | transaction / verified rollback | invoked only by forward/rollback engines with source guards; clears capability even on failure | propagated fatal state |
| `Transaction.begin` | new UUID directory, manifest, original/planned artifacts, journal events | source unchanged; application immutable | identity/current bytes, aligned ranges, no overlap, evidence class, mandatory guard/oracle; exclusive create and SHA-256 readback | FAILED_PREWRITE / FAILED_BACKUP / FAILED_BACKUP_VERIFY / FAILED_JOURNAL |
| `Transaction.run` | planned source sectors and readback artifacts | transaction; manual verified rollback on failure | chain/artifact integrity, fingerprint, per-patch old bytes, raw sync, exact readback, structural and available semantic oracles | distinct write/sync/readback/structural/semantic failure plus ROLLBACK_REQUIRED |
| `core.rollback` | exact original source sectors; new events | rollback transaction; original/planned states remain known | UUID, chain, manifest/artifact hashes, source identity, all byte preconditions, control, per-patch exact readback, normalized source samples/full hash | ROLLBACK_SOURCE_STATE_CHANGED / FAILED_DURABILITY / FAILED_READBACK / ROLLBACK_REQUIRED |
| `core.durable_create` / `durable_json` | new artifact only | source unchanged; never replace an artifact | exclusive creation, sync, reopen equality; POSIX directory fsync / Windows MoveFileExW WRITE_THROUGH without replacement | fatal OSError / FAILED_DURABILITY / FAILED_BACKUP_VERIFY |
| `MoveFileExW` | pending artifact -> exclusively published artifact | artifact publication, no source overwrite | no REPLACE_EXISTING flag; synced pending bytes; readback equality | fatal publish failure, pending artifact retained |
| `transaction_lock` | one-byte lock file | operational lock only | OS exclusive lock, released on process death | BLOCKED |
| `source_lock` / LockFileEx | source access control, no bytes | releases after verification | image whole-file locking / POSIX flock; physical offline control separately | BLOCKED / FAILED_STATE_RESTORE |
| `diskdoctor._atomic_write_json` | new report/metadata artifact | immutable output only | source-alias gate; exclusive durable create; no os.replace left in runtime | collision/durability failure |
| `dump_structures` | unique head/tail snapshot files | source unchanged | UUID names, exclusive durable create/hash; no longer authorizes transactions | fatal output failure |
| `dump_range` / `carve_vbk` | separate new extraction file | destination only; source read-only | source/volume alias checks, exclusive output, retry/explicit filler; byte count and extraction report | blocked collision / I/O error; unreadable bytes recorded |
| `imaging.make_image` writes | new image and chained checkpoints/badmap | destination only, resumable | source/output identities, exclusive creation, retries/sector descent, sync, prefix hash, final size, optional reopened full hash | BLOCKED_SOURCE_CHANGED / FAILED_WRITE / FAILED_READBACK / FAILED_JOURNAL |
| imaging `truncate` on resume | uncommitted tail of owned output only | destination checkpoint recovery | locked run, source identity and exact committed prefix/hash/size verified first | blocked mismatch; no source writes |
| `persist_report` / auto report / `_log` | new reports and explicit log file | output only | UUID report dirs, output-source identity/volume checks; source opens read-only; full machine report and human report | output error; auto cannot authorize source mutation |
| `DiskControl`, `win_set_offline`, `win_set_readonly` / Set-Disk | Windows operational disk flags | deliberately restored; not byte rollback | absolute non-system proof, captured identity/flags, independent offline/read-only confirmation and restored-state confirmation | BLOCKED_SYSTEM_DISK / BLOCKED_OFFLINE_FAILURE / FAILED_STATE_RESTORE |
| diskpart offline/online fallback | operational flags, unique temp script | same DiskControl rules | non-system/identity proof in caller; result independently queried before any raw write | offline/state-restore block |
| `win_rescan` / Update-HostStorageCache / diskpart rescan | OS presentation/cache | no source-byte transaction | explicit external action only; auto never calls it | external failure |
| `win_lock_dismount` / FSCTL_LOCK_VOLUME / FSCTL_DISMOUNT_VOLUME | volume operational mount state | not a source metadata patch | retained integration helper, not used as v2 write fallback; offline remains mandatory | handle/control failure |
| `run_chkdsk(fix=False)` | read-only utility check | read-only external | valid explicit drive letter; fix=True blocked outside audited external gate | external error |
| `external(chkdsk)` / subprocess chkdsk /f | arbitrary source filesystem metadata | NON_TRANSACTIONAL_EXTERNAL_MUTATION; byte rollback unsupported | exact target letter/disk binding, system block, fingerprint; separate --authorize-external-mutation and --apply; durable prepared/result logs | interruption/result error; semantic result UNKNOWN, never transactional recovery |
| `external(refsutil)` / `run_refsutil` | separate work/recovery destination | DESTINATION_ONLY_RECOVERY; source read-only | Windows volume IDs before mkdir; explicit target binding; prepared/result log; utility version mismatch parser retained | blocked volume alias / external error / version mismatch |
| generic `run_cmd` / `ps` | command-specific | classified by callers above | shell-free lists in authorized runtime paths; enumeration/geometry queries are read-only; no arbitrary user script CLI | timeout/error captured; never authorization |
| `NamedTemporaryFile` diskpart scripts | unique temporary output | source unchanged | exclusive random temp filename, fsync, retained for inspection | fatal output failure |
| `_Img`, `_mk_*`, `_put_*` helpers | newly generated synthetic images | tests only | no CLI route accepts a device; only explicit synthetic fixture construction; source SHA comparisons in regressions | test failure |
| `tests/baseline_v195.py` | historical synthetic test writes and mutable journals | historical reference only, NOT a v2 authorization path | original SHA-256 captured; runner loads only self-test and replaces forensic functions with current ones; original unsafe assumptions are covered by v2 rejection tests | reference assertion failure |
| unittest `os.replace`, `os.unlink`, direct writes | test fixture corruption/replacement | synthetic fault injection only | temporary directories; no physical devices; expected tamper/failure assertions | test assertion failure |
| Python compile/test runner | bytecode cache / temporary test files | development output only | normal filesystem permissions; no physical source | compile/test failure |

`os.rename`, `os.remove`, `os.unlink` and `os.replace` have no production source
mutation use. Artifact publication uses exclusive APIs, not replacing writes.
The baseline test reference intentionally retains historical APIs; it is a test
fixture and is not imported by normal diagnosis/repair execution.

Readback artifact failures are fatal too: bytes written without durable readback
evidence cannot commit. Operational-state changes are not falsely represented as
sector transactions. Storage corruption, malicious complete tree replacement and
device state behavior on real hardware remain outside synthetic-test guarantees.
