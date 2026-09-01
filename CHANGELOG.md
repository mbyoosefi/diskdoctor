# Changelog

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
