# Changelog

## 1.9.5
- `--find-name-file PATH`: read the --find-name search text from a file, the
  same protection --locate-verify-file already had. The identical shell
  quoting / BOM pitfalls could hit --find-name just as easily. T40 covers it.

## 1.9.4
- Fix: `--locate-verify-file` did not strip a leading UTF-8 BOM.
  PowerShell's `Out-File -Encoding utf8` always prepends an invisible BOM, so
  the needle silently began with an invisible character and matched nothing
  on disk -- the mechanism worked perfectly, but every candidate looked
  unverified. Now reads with `utf-8-sig`, which strips a BOM when present.

## 1.9.3
- `--locate-verify-file PATH`: read the --locate-verify search text from a
  file instead of the command line. A needle containing an embedded double
  quote (e.g. the VMDK descriptor pattern `VMFS "..."`) could be mis-escaped
  by PowerShell when passed inline, silently swallowing every flag after it
  (including --locate-verify-top-n) into the same argument -- exactly what
  happened in the field. Reading from a file sidesteps shell quoting
  entirely.

## 1.9.2
- Fix: `--locate-verify-top-n` was silently ignored. The underlying scorer
  always truncated its result list to the top 20 candidates *before* content
  verification ever saw them, so any value passed to `--locate-verify-top-n`
  (even in the thousands) only ever actually checked the first 20. On a dense
  repository the true candidate is often not in the top 20 by entropy score
  alone, so this bug could mean the real file was never tested. Fixed and
  pinned with regression test T37.

## 1.9.1
- `--locate-verify TEXT` (alongside `--locate-vbk`): on a dense repository,
  several neighbouring files can score identically on entropy/alignment --
  they are all compressed data with similarly-shaped boundaries. Entropy
  scoring alone can rank the wrong neighbour first, which is exactly what
  happened in the field (five ranked candidates, none the right file).
  This reads a real content probe (a few MB) from each top-scoring candidate
  and checks whether the given text (e.g. a VM name) actually appears near
  its start -- the pattern every genuine successful carve in this project
  has shown. T36 reproduces the exact failure (three same-size neighbours,
  target in the middle) and proves verification picks the true one.

## 1.9
- `--locate-vbk CENTER_LBA:SIZE_BYTES`: find the precise start of a
  known-exact-size file using Veeam block alignment (BlockAlignmentSize from
  the .vbm, typically 65536 bytes) instead of a linear margin guess. Carving
  tens or hundreds of GiB on a guessed offset is expensive, and being even a
  few bytes off produces a "Storage version not supported" error from Veeam
  even when the server version matches exactly. Scores thousands of
  alignment-snapped candidates using a few KB of reads each, ranking by
  whether content differs on both sides of the boundary. Read-only.

## 1.8
- `--find-vbm`: search for the actual content of a .vbm file (the documented
  `<BackupMeta>` XML root tag), not just its directory entry. Veeam has
  publicly declined to document the VBK/VIB storage format, but the .vbm
  metadata format is documented by third-party research (Synacktiv, 2024).
  Extracts FilePath, exact BackupSize, EncryptionState, JobName and more.
- `--carve-vbk CENTER_LBA:MARGIN_GIB`: convenience wrapper over --dump-range
  that extracts a large contiguous window around a known-good content offset,
  for handing to Veeam Extract Utility. No VBK start signature is claimed or
  guessed — the margin has to be generous enough to contain the true start.

## 1.7.1
- Noise filter for extracted strings. Compressed and encrypted data constantly
  produces short printable runs, which buried real filenames in junk. A run now
  qualifies only if it contains a genuine word (a CamelCase token of 4+ letters)
  or ends in a lowercase file extension. Measured on real dump output: 13/13
  real names kept, 82/84 noise strings dropped. `--dump-raw-strings` disables it.

## 1.7
- `--dump-range LBA:COUNT`: lift a raw sector range out to a file and print the
  printable strings inside it (ASCII and UTF-16LE). For pulling a small
  structure — a `.vbm`, a boot sector, a metadata node — off a volume whose
  filesystem can no longer locate it. Read-only.

## 1.6
- `--find-name`: search the raw disk for a filename independently of any
  filesystem. Names are stored as UTF-16LE in NTFS/ReFS/exFAT metadata, so a
  name can still be found byte-for-byte after the structures that locate the
  file are destroyed. Answers "was this file ever on this volume" when nothing
  else can. Read-only.

## 1.5.1
- Fix: `--triage-head-gib`, `--triage-head-samples` and `--baseline` were
  documented and read by the code but never registered with argparse, so any
  real `--triage` run crashed with AttributeError. Every test had built its
  Namespace with `_fake_args()` rather than the real parser, so the gap was
  invisible. A test now diffs every `args.*` the code reads against
  `build_parser()` output.

## 1.5
- `refsutil` has a ReFS-version ceiling tied to the Windows build it shipped
  with. When a volume's ReFS version exceeds it, `refsutil` fails with a
  misleading "volume does not contain a recognized file system" message even
  though it correctly identified the version one line earlier. DiskDoctor now
  parses this straight out of refsutil's own output (no hardcoded version
  table) and explains that this is a tool/OS-version mismatch, not corruption,
  with concrete next steps (newer Windows, an independent recovery tool, or
  Veeam Support).
- ReFS version is now shown in plan suggestions, warnings, and triage verdicts
  so it can be checked against `winver` before ever calling `refsutil`.

## 1.4
- Fixed a real false positive: high body entropy alone was being read as
  "widespread overwrite". A backup repository full of compressed files is
  high-entropy by design, healthy or not. Entropy is no longer treated as
  evidence without a control measurement on a known-healthy volume of the same
  workload (`--baseline`, or auto-selected in `--auto`).
  Added a dense head map (`--triage-head-gib`) and made the sequential
  forward-scan for the first recoverable structure always run (previously it
  was skipped exactly when the sampled map found nothing — the case it was
  needed most).

## 1.3
- `--auto`: one command, every disk, structural scan + conditional deep scan +
  triage + one text report + one JSON report. Read-only.

## 1.2
- Fixed several false positives found against real disks: saturated
  protective-MBR sector counts flagged as out-of-range; a side-unaware GPT
  geometry check flagging healthy backup headers; MSR/BIOS-boot/LDM partitions
  flagged as damaged RAW volumes; the NTFS-shaped extent-length model applied
  to ReFS (which need not fill its partition).
  Discovered ReFS *does* keep a volume-header copy near the end of the volume
  (contradicting v1.1's hard "no mirror" rule) and added it as scored
  evidence. Added `--triage` (read-only damage-depth assessment: boot sector,
  entropy, tail structure sweep, sampled damage map, forward edge scan,
  verdict) and `--deep-ignore-table` for when the partition table itself is
  suspect.

## 1.1
- Rewrite around an evidence engine: every candidate partition is scored on
  independent signals rather than a single boolean; volume length must be
  provable (partition-table entry, or a mirror boot sector validated against
  its own BPB and position), not just implied by a filesystem signature.
  Added the write gate (`SAFE_RESTORE` / `INFERRED_REBUILD` / `BLOCKED`),
  byte-for-byte GPT restores instead of regeneration, a journal-before-write
  transaction model with per-patch status and partial-crash undo, and a
  forensic imager with retry + explicit bad-sector map instead of silent
  zero-fill.

## 1.0
- Initial release: GPT/MBR/superfloppy/RAW detection, filesystem probes,
  signature-based deep scan, repair actions, undo journal, interactive wizard,
  self-test suite.
