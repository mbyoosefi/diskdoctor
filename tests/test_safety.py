import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import diskdoctor as dd
import diskdoctor_core as core
import diskdoctor_safety as safety
import diskdoctor_imaging as imaging


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, 'source.img')
        with open(self.path, 'wb') as f:
            f.write(bytes(1024 * 1024))
        self.disk = dd.RawDisk(self.path)
        self.addCleanup(self.disk.close)
        self.root = os.path.join(self.temp.name, 'transactions')
        self.writes = 0
        original = self.disk.write_at
        def counted(*a):
            self.writes += 1
            return original(*a)
        self.disk.write_at = counted
        self.good = lambda d: {'state': 'VERIFIED', 'oracle': 'synthetic independent oracle'}

    def tx(self, structural=None, semantic=None, fault=None, patches=None, guard=None):
        patches = patches or [dd.Patch(512, b'A' * 512, 'synthetic', old=bytes(512))]
        return core.Transaction(self.disk, 'synthetic', patches, self.root,
                                core.fingerprint(self.disk), {'fixture': True},
                                structural or self.good, semantic, 'PROVEN_REDUNDANT_COPY',
                                guard or (lambda: None), fault)

    def start(self, **kw):
        tx = self.tx(**kw)
        tx.begin()
        self.disk.reopen(True)
        return tx

    def rollback(self, tx, fault=None):
        self.disk.close()
        return core.rollback(self.root, tx.transaction_id,
                             lambda p, s, b: dd.RawDisk(p, sector_size=s, base_offset=b),
                             lambda d: safety.DiskControl(dd, d), fault)

    def test_complete_requires_all_oracles(self):
        tx = self.start(semantic=self.good)
        tx.run()
        doc = core.inspect_transaction(self.root, tx.transaction_id)
        self.assertEqual(doc['state'], 'COMMITTED')
        self.assertEqual(core.read_json(os.path.join(tx.directory, 'verification.json'))['verdict'], 'RECOVERED_VERIFIED')

    def test_unknown_semantics_is_partial(self):
        tx = self.start()
        tx.run()
        self.assertEqual(core.read_json(os.path.join(tx.directory, 'verification.json'))['verdict'], 'RECOVERY_PARTIAL')

    def test_force_cannot_bypass_current_bytes(self):
        tx = self.start()
        with open(self.path, 'r+b') as f:
            f.seek(512)
            f.write(b'X')
        with self.assertRaises(core.SafetyError):
            tx.run(force=True)
        self.assertEqual(self.writes, 0)

    def test_force_cannot_bypass_guard(self):
        guard = mock.Mock(side_effect=core.SafetyError('BLOCKED_SYSTEM_DISK'))
        with self.assertRaises(core.SafetyError):
            self.tx(guard=guard).begin()
        self.assertEqual(self.writes, 0)

    def test_source_replacement_blocks_write(self):
        tx = self.start()
        # Closing first permits replacement on Windows; retain same path/size.
        self.disk.close()
        replacement = self.path + '.replacement'
        with open(replacement, 'wb') as f:
            f.write(bytes(1024 * 1024))
        os.replace(replacement, self.path)
        self.disk.reopen(True)
        with self.assertRaises(core.SafetyError):
            tx.run()
        self.assertEqual(self.writes, 0)

    def test_backup_corruption_blocks_write(self):
        tx = self.start()
        with open(os.path.join(tx.directory, 'original.bin'), 'r+b') as f:
            f.write(b'X')
        with self.assertRaises(core.SafetyError):
            tx.run(force=True)
        self.assertEqual(self.writes, 0)

    def test_planned_artifact_corruption_blocks_write(self):
        tx = self.start()
        with open(os.path.join(tx.directory, 'planned.bin'), 'r+b') as f:
            f.write(b'X')
        with self.assertRaises(core.SafetyError):
            tx.run()
        self.assertEqual(self.writes, 0)

    def test_journal_failure_zero_writes(self):
        tx = self.tx()
        with mock.patch.object(core, 'durable_json', side_effect=OSError('fsync failed')):
            with self.assertRaises(OSError):
                tx.begin()
        self.assertEqual(self.writes, 0)

    def test_backup_readback_mismatch_blocks_write(self):
        tx = self.tx()
        create = core.durable_create
        def corrupt(path, data):
            create(path, data)
            if path.endswith('original.bin'):
                with open(path, 'r+b') as f:
                    f.write(b'X')
        with mock.patch.object(core, 'durable_create', side_effect=corrupt):
            with self.assertRaises(core.SafetyError):
                tx.begin()
        self.assertEqual(self.writes, 0)

    def test_same_second_transaction_ids_unique(self):
        first, second = self.tx(), self.tx()
        first.begin()
        second.begin()
        self.assertNotEqual(first.transaction_id, second.transaction_id)
        self.assertTrue(os.path.isdir(first.directory))
        self.assertTrue(os.path.isdir(second.directory))

    def test_events_append_only(self):
        tx = self.start()
        event = os.path.join(tx.directory, 'events', '0000_PLANNED.json')
        before = core.file_hash(event)
        tx.run()
        self.assertEqual(core.file_hash(event), before)
        with self.assertRaises((OSError, core.SafetyError)):
            core.durable_create(event, b'overwrite')
        self.assertEqual(core.file_hash(event), before)

    def test_chain_tampering_detected(self):
        tx = self.start()
        event = os.path.join(tx.directory, 'events', '0000_PLANNED.json')
        doc = core.read_json(event)
        doc['state'] = 'COMMITTED'
        with open(event, 'w') as f:
            json.dump(doc, f)
        with self.assertRaises(core.SafetyError):
            core.inspect_transaction(self.root, tx.transaction_id)
        self.assertEqual(self.writes, 0)

    def test_deleted_event_detected(self):
        tx = self.start()
        os.unlink(os.path.join(tx.directory, 'events', '0001_BACKUP_CREATED.json'))
        with self.assertRaises(core.SafetyError):
            tx.run()

    def test_manifest_tampering_detected(self):
        tx = self.start()
        doc = core.read_json(tx.path)
        doc['patches'][0]['offset'] += 512
        with open(tx.path, 'w') as f:
            json.dump(doc, f)
        with self.assertRaises(core.SafetyError):
            tx.run()

    def test_write_durability_is_fatal(self):
        tx = self.start()
        # Patch only source fsync; artifact syncs remain functional.
        original = os.fsync
        def sync(fd):
            if fd == self.disk.fh.fileno():
                raise OSError('source flush failure')
            return original(fd)
        with mock.patch.object(os, 'fsync', side_effect=sync):
            with self.assertRaises(core.SafetyError) as e:
                tx.run(force=True)
        self.assertEqual(e.exception.state, 'FAILED_DURABILITY')
        states = [e['state'] for e in core.inspect_transaction(self.root, tx.transaction_id)['events']]
        self.assertNotIn('WRITE_COMPLETED', states)
        self.assertNotIn('COMMITTED', states)

    def test_force_cannot_bypass_readback(self):
        tx = self.start()
        def ignored(*a):
            self.writes += 1
            return 512
        self.disk.write_at = ignored
        with self.assertRaises(core.SafetyError) as e:
            tx.run(force=True)
        self.assertEqual(e.exception.state, 'FAILED_READBACK')
        self.assertEqual(tx.state, 'ROLLBACK_REQUIRED')

    def test_structural_failure_prevents_commit(self):
        tx = self.start(structural=lambda d: {'state': 'FAILED'})
        with self.assertRaises(core.SafetyError) as e:
            tx.run()
        self.assertEqual(e.exception.state, 'FAILED_STRUCTURAL_VERIFY')
        self.assertEqual(tx.state, 'ROLLBACK_REQUIRED')

    def test_semantic_failure_prevents_recovered(self):
        tx = self.start(semantic=lambda d: {'state': 'UNKNOWN'})
        with self.assertRaises(core.SafetyError) as e:
            tx.run()
        self.assertEqual(e.exception.state, 'FAILED_SEMANTIC_VERIFY')
        self.assertFalse(os.path.exists(os.path.join(tx.directory, 'verification.json')))

    def test_rollback_verified_and_idempotent(self):
        tx = self.start()
        tx.run()
        self.assertEqual(self.rollback(tx), 512)
        self.assertEqual(core.inspect_transaction(self.root, tx.transaction_id)['state'], 'ROLLED_BACK_VERIFIED')
        with open(self.path, 'rb') as f:
            self.assertEqual(f.read(), bytes(1024 * 1024))
        self.assertEqual(self.rollback(tx), 0)

    def test_rollback_unexpected_bytes_blocked(self):
        tx = self.start()
        tx.run()
        with open(self.path, 'r+b') as f:
            f.seek(512)
            f.write(b'X')
        before = core.file_hash(self.path)
        with self.assertRaises(core.SafetyError) as e:
            self.rollback(tx)
        self.assertEqual(e.exception.state, 'ROLLBACK_SOURCE_STATE_CHANGED')
        self.assertEqual(core.file_hash(self.path), before)

    def test_rollback_untouched_sample_mismatch(self):
        tx = self.start()
        tx.run()
        with open(self.path, 'r+b') as f:
            f.seek(16)
            f.write(b'X')
        with self.assertRaises(core.SafetyError):
            self.rollback(tx)

    def test_rollback_target_replaced(self):
        tx = self.start()
        tx.run()
        self.disk.close()
        with open(self.path + '.new', 'wb') as f:
            f.write(bytes(1024 * 1024))
        os.replace(self.path + '.new', self.path)
        with self.assertRaises(core.SafetyError):
            self.rollback(tx)

    def test_interrupted_rollback_detectable_and_recoverable(self):
        tx = self.start()
        tx.run()
        with self.assertRaises(RuntimeError):
            self.rollback(tx, fault=lambda point: (_ for _ in ()).throw(RuntimeError('crash')))
        self.assertTrue(core.inspect_transaction(self.root, tx.transaction_id)['interrupted'])
        self.assertEqual(self.rollback(tx), 512)

    def test_base_offset_round_trip(self):
        self.disk.close()
        self.disk = dd.RawDisk(self.path, base_offset=4096)
        self.addCleanup(self.disk.close)
        tx = self.start()
        tx.run()
        self.assertEqual(self.rollback(tx), 512)
        with open(self.path, 'rb') as f:
            self.assertEqual(f.read(), bytes(1024 * 1024))

    def test_overlapping_patches_blocked(self):
        with self.assertRaises(core.SafetyError):
            self.tx(patches=[dd.Patch(512, b'A'*512, 'a', bytes(512)),
                             dd.Patch(768, b'B'*512, 'b', bytes(512))]).begin()
        self.assertEqual(self.writes, 0)

    def test_direct_raw_write_blocked(self):
        self.disk.reopen(True)
        with self.assertRaises(dd.DiskError):
            self.disk.write_at(0, b'X')

    def test_unknown_evidence_remains_unknown(self):
        ev = dd.Evidence('synthetic')
        ev.set('unavailable', None)
        self.assertEqual(ev.to_dict()['signals']['unavailable']['state'], 'UNKNOWN')

    def test_rollback_readback_mismatch_not_success(self):
        tx = self.start()
        tx.run()
        self.disk.close()
        with mock.patch.object(dd.RawDisk, 'write_at', return_value=512):
            with self.assertRaises(core.SafetyError) as e:
                self.rollback(tx)
        self.assertEqual(e.exception.state, 'FAILED_READBACK')
        self.assertNotEqual(core.inspect_transaction(self.root, tx.transaction_id)['state'], 'ROLLED_BACK_VERIFIED')

    def test_full_hash_detects_unsampled_changes(self):
        tx = self.tx()
        tx.source = core.fingerprint(self.disk, full=True)
        tx.begin()
        self.disk.reopen(True)
        tx.run()
        with open(self.path, 'r+b') as f:
            f.seek(200000)
            f.write(b'X')
        with self.assertRaises(core.SafetyError):
            self.rollback(tx)

    def test_full_hash_rollback_round_trip(self):
        tx = self.tx()
        tx.source = core.fingerprint(self.disk, full=True)
        tx.begin()
        self.disk.reopen(True)
        tx.run()
        self.assertEqual(self.rollback(tx), 512)

    def test_source_short_write_fatal(self):
        tx = self.start()
        fh = self.disk.fh
        self.disk.fh = mock.Mock(wraps=fh)
        self.disk.fh.write.return_value = 4
        with self.assertRaises(core.SafetyError) as e:
            tx.run()
        self.assertEqual(e.exception.state, 'FAILED_WRITE')
        self.assertEqual(tx.state, 'ROLLBACK_REQUIRED')
        self.disk.fh = fh

    def test_pending_crash_detectable(self):
        tx = self.start()
        self.assertTrue(core.inspect_transaction(self.root, tx.transaction_id)['interrupted'])
        self.assertEqual(self.writes, 0)

    def test_rolled_back_source_replacement_still_blocked(self):
        tx = self.start()
        tx.run()
        self.rollback(tx)
        with open(self.path + '.new', 'wb') as f:
            f.write(bytes(1024 * 1024))
        os.replace(self.path + '.new', self.path)
        with self.assertRaises(core.SafetyError):
            self.rollback(tx)

    def test_readback_artifact_tampering_detected(self):
        tx = self.start()
        tx.run()
        with open(os.path.join(tx.directory, 'readback_0000.bin'), 'r+b') as f:
            f.write(b'X')
        with self.assertRaises(core.SafetyError):
            core.inspect_transaction(self.root, tx.transaction_id)


FAULT_POINTS = ('before_backup', 'after_backup_creation', 'after_backup_fsync',
                'after_journal_prepared', 'immediately_before_write',
                'immediately_after_write', 'before_readback', 'after_readback',
                'before_structural_verify', 'during_structural_verify', 'before_commit')


def fault_test(point):
    def test(self):
        def fault(actual):
            if actual == point:
                raise RuntimeError('injected crash at ' + point)
        tx = self.tx(fault=fault)
        with self.assertRaises(RuntimeError):
            tx.begin()
            self.disk.reopen(True)
            tx.run()
        doc = core.inspect_transaction(self.root, tx.transaction_id)
        self.assertNotEqual(doc['state'], 'COMMITTED')
        mutated = point in FAULT_POINTS[5:]
        self.assertEqual(self.writes, 1 if mutated else 0)
        if mutated:
            self.assertEqual(self.rollback(tx), 512)
    return test


for _point in FAULT_POINTS:
    setattr(TransactionTests, 'test_fault_' + _point, fault_test(_point))


class WindowsStateTests(unittest.TestCase):
    def setUp(self):
        self.disk = mock.Mock(is_device=True, path=r'\\.\PhysicalDrive9', size=4096, base=0)
        self.state = {'Disk': {'Number': 9, 'Size': 4096, 'UniqueId': 'unit', 'SerialNumber': 'serial',
                               'IsOffline': False, 'IsReadOnly': False, 'IsBoot': False, 'IsSystem': False},
                      'Volumes': [], 'CriticalLetters': []}
        self.dd = mock.Mock(IS_WIN=True, IS_LINUX=False)
        self.dd.is_admin.return_value = True
        self.order = []
        def offline(index, value):
            self.order.append('offline' if value else 'online')
            self.state['Disk']['IsOffline'] = value
            return True
        def readonly(index, value):
            self.order.append('readonly' if value else 'writable')
            self.state['Disk']['IsReadOnly'] = value
            return True
        self.dd.win_set_offline.side_effect = offline
        self.dd.win_set_readonly.side_effect = readonly
        patch = mock.patch.object(safety, 'windows_state', side_effect=lambda *a: json.loads(json.dumps(self.state)))
        patch.start()
        self.addCleanup(patch.stop)

    def test_system_disk_absolute_block(self):
        self.state['Disk']['IsSystem'] = True
        with self.assertRaises(core.SafetyError) as e:
            with safety.DiskControl(self.dd, self.disk):
                self.fail('entered system disk')
        self.assertEqual(e.exception.state, 'BLOCKED_SYSTEM_DISK')
        self.assertEqual(self.order, [])

    def test_pagefile_disk_absolute_block(self):
        self.state['Volumes'] = [{'DriveLetter': 'P'}]
        self.state['CriticalLetters'] = ['P']
        with self.assertRaises(core.SafetyError):
            with safety.DiskControl(self.dd, self.disk):
                self.fail()

    def test_offline_failure_blocks_before_body(self):
        self.dd.win_set_offline.side_effect = lambda *a: False
        with self.assertRaises(core.SafetyError):
            with safety.DiskControl(self.dd, self.disk):
                self.fail('mutation body must not run')

    def test_independent_offline_confirmation(self):
        self.dd.win_set_offline.side_effect = lambda *a: True
        with self.assertRaises(core.SafetyError):
            with safety.DiskControl(self.dd, self.disk):
                self.fail()

    def test_original_readonly_restored_after_verification(self):
        self.state['Disk']['IsReadOnly'] = True
        with safety.DiskControl(self.dd, self.disk) as guard:
            guard()
            self.order.append('verified')
        self.assertTrue(self.state['Disk']['IsReadOnly'])
        self.assertFalse(self.state['Disk']['IsOffline'])
        self.assertLess(self.order.index('verified'), self.order.index('online'))
        self.assertLess(self.order.index('readonly'), self.order.index('online'))

    def test_original_offline_preserved(self):
        self.state['Disk']['IsOffline'] = True
        with safety.DiskControl(self.dd, self.disk):
            self.order.append('verified')
        self.assertTrue(self.state['Disk']['IsOffline'])
        self.assertNotIn('online', self.order)

    def test_state_restore_failure_is_explicit(self):
        with self.assertRaises(core.SafetyError) as e:
            with safety.DiskControl(self.dd, self.disk):
                self.dd.win_set_offline.side_effect = lambda *a: False
        self.assertEqual(e.exception.state, 'FAILED_STATE_RESTORE')


class IntegrationTests(TransactionTests):
    # Reuse fixtures, but do not duplicate the inherited unit tests.
    def gpt(self):
        total = self.disk.sectors
        layout = dd.build_gpt(total, 512, [{'first': 256, 'last': 1000,
                                        'type_guid': dd.GUID_MSDATA, 'part_guid': str(core.uuid.uuid4()),
                                        'name': 'historical', 'attrs': 0}], disk_guid=str(core.uuid.uuid4()))
        self.disk.close()
        with open(self.path, 'r+b') as f:
            for off, data in ((0, dd.build_protective_mbr(total)),
                              (layout['backup_entries_lba']*512, layout['backup_entries']),
                              (layout['backup_header_lba']*512, layout['backup_header'])):
                f.seek(off)
                f.write(data)
        self.disk.reopen(False)
        return layout

    def args(self, *extra):
        return dd.build_parser().parse_args(['--disk', self.path, '--state-dir', self.temp.name,
                                             '--yes', '--quiet', '--no-color'] + list(extra))

    def test_real_gpt_restore_and_rollback(self):
        self.gpt()
        before = core.file_hash(self.path)
        with contextlib.redirect_stdout(io.StringIO()):
            r = dd.scan(self.disk)
            self.assertEqual(dd.execute_action(self.disk, r, self.args('--apply'), 'gpt-restore-primary'), dd.EXIT_OK)
        self.assertTrue(dd.read_gpt(self.disk)['valid'])
        tids = os.listdir(self.root)
        self.assertEqual(len(tids), 1)
        self.disk.close()
        args = self.args('--undo', tids[0])
        safety.undo(dd, args)
        self.assertEqual(core.file_hash(self.path), before)

    def test_force_cannot_bypass_disk_blockers(self):
        self.gpt()
        r = dd.scan(self.disk)
        r.block('synthetic-block', 'must not bypass')
        before = core.file_hash(self.path)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = dd.execute_action(self.disk, r, self.args('--apply', '--force'), 'gpt-restore-primary')
        self.assertEqual(rc, dd.EXIT_BLOCKED)
        self.assertEqual(core.file_hash(self.path), before)

    def test_gpt_geometry_requires_size_provenance(self):
        self.gpt()
        r = dd.scan(self.disk)
        with self.assertRaises(dd.Blocked):
            dd.act_gpt_fix_geometry(self.disk, r, self.args('--force', '--allow-inferred'))

    def test_gpt_rebuild_no_identity_invention(self):
        self.gpt()
        r = dd.scan(self.disk)
        with self.assertRaises(dd.Blocked), mock.patch.object(dd, 'new_guid', side_effect=AssertionError('invented identity')):
            dd.act_gpt_rebuild(self.disk, r, self.args('--apply', '--force'))

    def test_mbr_rebuild_does_not_invent_active_flag(self):
        self.disk.close()
        img = dd._Img(self.path, 64 * dd.MIB)
        dd._put_ntfs(img, 2048, 32768)
        self.disk = dd.RawDisk(self.path)
        self.addCleanup(self.disk.close)
        r = dd.scan(self.disk, deep=True, deep_step=512)
        act = dd.act_mbr_rebuild(self.disk, r, self.args('--apply'))
        self.assertEqual(act.patches[0].new[0x1be], 0)
        self.assertEqual(act.write_class, 'INFERRED_GEOMETRY')
        before = core.file_hash(self.path)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(dd.execute_action(self.disk, r, self.args('--apply', '--allow-inferred', '--force'), 'mbr-rebuild'), dd.EXIT_BLOCKED)
        self.assertEqual(core.file_hash(self.path), before)

    def test_crc_requires_independent_valid_copy(self):
        r = dd.scan(self.disk)
        with self.assertRaises(dd.Blocked):
            dd.act_gpt_fix_crc(self.disk, r, self.args())

    def test_auto_zero_writes_with_mutation_options(self):
        self.gpt()
        before = core.file_hash(self.path)
        args = self.args('--auto', '--apply', '--force', '--action', 'gpt-restore-primary',
                         '--auto-deep-seconds', '1', '--auto-out', os.path.join(self.temp.name, 'auto'))
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(dd.RawDisk, 'write_at', side_effect=AssertionError('auto wrote')):
            self.assertEqual(dd.auto_run(args), dd.EXIT_OK)
        self.assertEqual(core.file_hash(self.path), before)

    def test_incomplete_search_not_complete_absence(self):
        res = dd.find_name(self.disk, 'not-present', limit=512)
        self.assertFalse(res['source_complete'])
        self.assertEqual(res['absence_state'], 'UNKNOWN')

    def test_external_mutator_separate_authorization(self):
        self.assertEqual(safety.classify('chkdsk'), 'BLOCKED')
        self.assertFalse(self.args('--apply', '--force').authorize_external_mutation)

    def test_image_resume_and_collision(self):
        out = os.path.join(self.temp.name, 'out.img')
        fault = mock.Mock(side_effect=RuntimeError('crash'))
        with self.assertRaises(RuntimeError):
            imaging.make_image(dd, self.disk, out, chunk=65536, fault=fault)
        with self.assertRaises(core.SafetyError):
            imaging.make_image(dd, self.disk, out)
        imaging.make_image(dd, self.disk, out, chunk=65536, resume=True, final_hash=True)
        self.assertEqual(core.file_hash(out), core.file_hash(self.path))
        self.assertEqual(imaging.load_checkpoint(out + '.checkpoints')['state'], 'DONE_CHECKED')

    def test_image_resume_source_changed_blocked(self):
        out = os.path.join(self.temp.name, 'out.img')
        with self.assertRaises(RuntimeError):
            imaging.make_image(dd, self.disk, out, chunk=65536, fault=mock.Mock(side_effect=RuntimeError()))
        with open(self.path, 'r+b') as f:
            f.write(b'X')
        with self.assertRaises(core.SafetyError):
            imaging.make_image(dd, self.disk, out, chunk=65536, resume=True)

    def test_image_resume_output_tampering_blocked(self):
        out = os.path.join(self.temp.name, 'out.img')
        with self.assertRaises(RuntimeError):
            imaging.make_image(dd, self.disk, out, chunk=65536, fault=mock.Mock(side_effect=RuntimeError()))
        with open(out, 'r+b') as f:
            f.write(b'X')
        with self.assertRaises(core.SafetyError):
            imaging.make_image(dd, self.disk, out, chunk=65536, resume=True)

    def test_dump_output_collision_blocked(self):
        out = os.path.join(self.temp.name, 'dump.bin')
        with open(out, 'wb') as f:
            f.write(b'existing')
        with self.assertRaises(FileExistsError):
            dd.dump_range(self.disk, 0, 1, out)
        with open(out, 'rb') as f:
            self.assertEqual(f.read(), b'existing')

    def test_auto_report_cannot_alias_source(self):
        before = core.file_hash(self.path)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = dd.auto_run(self.args('--auto', '--apply', '--force', '--auto-out', self.path))
        self.assertEqual(rc, dd.EXIT_BLOCKED)
        self.assertEqual(core.file_hash(self.path), before)

    def test_json_and_log_source_aliases_blocked(self):
        for option in ('--json', '--log'):
            args = self.args(option, self.path)
            with self.assertRaises(core.SafetyError):
                safety.protect_outputs(dd, args)

    def test_competing_valid_gpt_copies_blocked(self):
        layout = self.gpt()
        with open(self.path, 'r+b') as f:
            f.seek(512)
            f.write(layout['primary_header'])
            f.seek(1024)
            f.write(layout['primary_entries'])
            header = bytearray(layout['primary_header'])
            header[56:72] = bytes.fromhex('11' * 16)
            import struct
            struct.pack_into('<I', header, 16, 0)
            struct.pack_into('<I', header, 16, dd.crc32(header[:92]))
            f.seek(512)
            f.write(header)
        r = dd.scan(self.disk)
        self.assertTrue(r.gpt_p['valid'] and r.gpt_b['valid'])
        with self.assertRaises(dd.Blocked):
            dd.act_gpt_restore_primary(self.disk, r, self.args('--apply', '--force'))

    def test_gpt_structural_oracle_is_independent(self):
        self.gpt()
        result = safety.verify_gpt(dd, self.disk)
        self.assertEqual(result['state'], 'FAILED')  # primary still absent

    def test_imaging_unreadable_head_preserves_sector_descent(self):
        read = self.disk.read_at
        def damaged(off, n):
            if off < 512 and off+n > 0:
                raise dd.DiskError('unreadable sector')
            return read(off, n)
        self.disk.read_at = damaged
        out = os.path.join(self.temp.name, 'bad.img')
        imaging.make_image(dd, self.disk, out, chunk=65536, retries=1)
        bad = core.read_json(out + '.badmap.json')
        self.assertEqual(bad['unreadable_bytes'], 512)
        self.assertEqual(bad['bad_ranges'][0]['start'], 0)
        with open(out, 'rb') as f:
            self.assertTrue(f.read(32).startswith(b'DISKDOCTOR-UNREADABLE'))
        self.assertEqual(bad['source_fingerprint']['samples'][0]['state'], 'UNKNOWN')

    def test_raw_short_search_remains_unknown(self):
        with mock.patch.object(self.disk, 'read_at', return_value=b'no data'*4):
            res = dd.find_name(self.disk, 'absent')
            vbm = dd.find_vbm_metadata(self.disk)
        self.assertFalse(res['source_complete'])
        self.assertFalse(vbm['source_complete'])
        self.assertEqual(res['absence_state'], 'UNKNOWN')

    def test_deep_limit_reports_exact_scope(self):
        dd.deep_scan(self.disk, limit=65536)
        self.assertFalse(self.disk._last_deep_scope['source_complete'])
        self.assertTrue(self.disk._last_deep_scope['scope_complete'])

    def test_rejected_hypothesis_requires_material_change(self):
        act = dd.RepairAction('synthetic', 'test', [dd.Patch(512, b'A'*512, 'fixture', bytes(512))], dd.GATE_SAFE)
        act.source_fingerprint = core.fingerprint(self.disk)
        act.provenance = {'fixture': True}
        safety.rejection_gate(self.root, act)
        tx = self.tx(structural=lambda d: {'state': 'FAILED'})
        tx.provenance = act.provenance
        tx.begin()
        self.disk.reopen(True)
        with self.assertRaises(core.SafetyError):
            tx.run()
        self.rollback(tx)
        self.disk.reopen(False)
        act.source_fingerprint = core.fingerprint(self.disk)
        with self.assertRaises(core.SafetyError):
            safety.rejection_gate(self.root, act)
        act.provenance['size_oracle'] = {'state': 'OPERATOR_SUPPLIED', 'provenance': 'new authoritative measurement', 'bytes': self.disk.size}
        safety.rejection_gate(self.root, act)
        self.assertIn('size_oracle', act.provenance['prior_rejections'][0]['changed_variables'])

    def test_ast_preserves_forensic_algorithms_and_aligned_reads(self):
        import ast
        from pathlib import Path
        baseline = ast.parse(Path('tests/baseline_v195.py').read_text(encoding='utf-8'))
        current = ast.parse(Path('diskdoctor.py').read_text(encoding='utf-8'))
        bm = {n.name: n for n in baseline.body if isinstance(n, ast.FunctionDef)}
        cm = {n.name: n for n in current.body if isinstance(n, ast.FunctionDef)}
        preserved = ('probe_fs', 'parse_mbr', 'walk_extended', 'parse_gpt_header', 'read_gpt',
                     'build_evidence', 'mark_overlaps', 'triage_partition', 'triage_verdict',
                     'scan_refs_header_near_end', 'locate_vbk_start', 'locate_vbk_start_verified',
                     'verify_vbk_candidate', 'parse_refsutil_version_mismatch', '_read_retry')
        for name in preserved:
            self.assertEqual(ast.dump(bm[name]), ast.dump(cm[name]), name)
        braw = next(n for n in baseline.body if isinstance(n, ast.ClassDef) and n.name == 'RawDisk')
        craw = next(n for n in current.body if isinstance(n, ast.ClassDef) and n.name == 'RawDisk')
        b = next(n for n in braw.body if isinstance(n, ast.FunctionDef) and n.name == 'read_at')
        c = next(n for n in craw.body if isinstance(n, ast.FunctionDef) and n.name == 'read_at')
        self.assertEqual(ast.dump(b), ast.dump(c))

    def test_ntfs_restore_requires_readable_metadata_and_mirror(self):
        import struct
        self.disk.close()
        img = dd._Img(self.path, 64 * dd.MIB)
        dd._put_ntfs(img, 2048, 32768)
        vbr = bytearray(img.read(2048, 1))
        vbr[0x40] = 0xF6  # Explicit 1024-byte FILE record geometry.
        img.put(2048, bytes(vbr))
        img.put(2048 + 32768 - 1, bytes(vbr))
        fields = dd.ntfs_fields(vbr)
        first = 2048 * 512 + fields['mft_lcn'] * fields['bps'] * fields['spc']
        mirror = 2048 * 512 + fields['mftmirr_lcn'] * fields['bps'] * fields['spc']
        records = []
        for i in range(4):
            record = bytearray(1024)
            record[:4] = b'FILE'
            struct.pack_into('<HH', record, 4, 48, 3)
            struct.pack_into('<H', record, 0x10, i+1)
            struct.pack_into('<HHII', record, 0x14, 64, 1, 164, 1024)
            struct.pack_into('<II', record, 64, 0x10, 96)
            struct.pack_into('<IH', record, 80, 72, 24)
            struct.pack_into('<I', record, 160, 0xffffffff)
            record[48:50] = b'AB'
            record[510:512] = b'AB'
            record[1022:1024] = b'AB'
            records.append(bytes(record))
        with open(self.path, 'r+b') as f:
            f.seek(first)
            f.write(b''.join(records))
            f.seek(mirror)
            f.write(records[0])
            f.seek(0)
            mbr = bytearray(512)
            mbr[0x1be:0x1ce] = dd.build_mbr_entry(7, 2048, 32768)
            mbr[510:512] = b'\x55\xaa'
            f.write(mbr)
            f.seek(2048*512)
            f.write(bytes(512))
        self.disk = dd.RawDisk(self.path)
        self.addCleanup(self.disk.close)
        r = dd.scan(self.disk)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = dd.execute_action(self.disk, r, self.args('--apply', '--part', '1'), 'vbr-restore')
        self.assertEqual(rc, dd.EXIT_OK)
        tid = os.listdir(self.root)[0]
        result = core.read_json(os.path.join(self.root, tid, 'verification.json'))
        self.assertEqual(result['semantic']['state'], 'VERIFIED')
        self.assertEqual(result['verdict'], 'RECOVERED_VERIFIED')


# Avoid running inherited unit tests twice while sharing setUp and helpers.
for _name in list(TransactionTests.__dict__):
    if _name.startswith('test_'):
        setattr(IntegrationTests, _name, None)


if __name__ == '__main__':
    dd.QUIET = True
    unittest.main()
