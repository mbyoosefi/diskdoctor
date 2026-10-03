"""Run original field scenarios with current forensic functions and v2 safety.

Legacy write authorizations are exercised only inside the immutable reference
fixture, on images it creates. V2 mutations are tested in test_safety.
"""
import importlib.util
import os
import sys
import unittest


PRESERVED = (
    'probe_fs', '_looks_like_fat32', 'ntfs_fields', 'ntfs_fields_sane',
    'exfat_fields', 'fat_fields', 'fat_fields_sane', 'exfat_vbr_checksum',
    'exfat_checksum_ok', 'bpb_match', 'parse_mbr', 'walk_extended',
    'parse_gpt_header', 'read_gpt', 'gpt_entries_plausible', 'build_evidence',
    '_ntfs_why', '_fat_why', '_fat_geometry_ok', '_ntfs_mirror_evidence',
    '_fat32_mirror_evidence', '_exfat_mirror_evidence', '_detect_mirror_copy',
    'refs_superblock_evidence', 'mark_overlaps', 'scan', 'probe_partition_fs',
    'sweep_common_offsets', 'deep_scan', 'dedup_parts', 'collect_disk_blockers',
    'collect_warnings', 'entropy', 'parse_refs_header', 'find_refs_header_copy',
    'scan_refs_header_near_end', 'find_structures', 'classify_region', 'damage_map',
    'head_map', 'extract_strings', 'looks_like_text', 'parse_vbm_fields',
    'find_vbm_metadata', 'locate_vbk_start', 'verify_vbk_candidate',
    'locate_vbk_start_verified', 'find_name', 'find_first_structure',
    'control_baseline', 'pick_control', 'triage_partition', 'triage_verdict',
    'run_triage', 'parse_refsutil_version_mismatch', 'auto_one', 'auto_run')


def run():
    import diskdoctor as dd
    path = os.path.join(os.path.dirname(__file__), 'baseline_v195.py')
    spec = importlib.util.spec_from_file_location('diskdoctor_reference', path)
    reference = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = reference
    spec.loader.exec_module(reference)
    for name in PRESERVED:
        setattr(reference, name, getattr(dd, name))
    old = dd.QUIET
    dd.QUIET = True
    try:
        print('Field regression: original 229 assertions using current forensic engine')
        field = reference.self_test()
        suite = unittest.defaultTestLoader.discover(os.path.dirname(__file__), pattern='test_*.py',
                                                    top_level_dir=os.path.dirname(os.path.dirname(__file__)))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return dd.EXIT_OK if field == 0 and result.wasSuccessful() else dd.EXIT_TESTFAIL
    finally:
        dd.QUIET = old


if __name__ == '__main__':
    sys.exit(run())
