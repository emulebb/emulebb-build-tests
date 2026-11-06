from dataclasses import replace
from contextlib import closing
import json
import sqlite3
import tracemalloc

import pytest

from emule_test_harness import emule_profile_export as export, mfc_known_met as known
from emule_test_harness.profile_exchange import write_exchange, SCHEMA
from test_emule_profile_export import _write_mfc_profile, _write_job


def job_fixture(tmp_path):
    profile=tmp_path/'profile'
    config=_write_mfc_profile(profile)
    config_job=tmp_path/'job.toml'
    _write_job(config_job,source_profile=profile,output_manifest=tmp_path/'exchange.sqlite')
    return export.load_export_job(config_job), config


def test_exchange_packs_recovery_and_is_closed_portable_database(tmp_path,monkeypatch):
    job,config=job_fixture(tmp_path)
    entry=replace(known.parse_known_met(config/'known.met')[0],aich_root='11'*20)
    monkeypatch.setattr(known,'iter_known_met',lambda path:iter([entry]))
    (config/'known2_64.met').write_bytes(b'\x02'+bytes.fromhex(entry.aich_root)+(1).to_bytes(4,'little')+bytes.fromhex(entry.aich_root))
    result=write_exchange(job,hashes_only=True)
    assert result['summary']['recoverySets']==1
    with closing(sqlite3.connect(job.output_manifest)) as db:
        assert json.loads(db.execute('SELECT value FROM header').fetchone()[0])['schema']==SCHEMA
        assert db.execute('SELECT leaves FROM recovery_parts').fetchone()[0]==bytes.fromhex(entry.aich_root)
        assert db.execute('SELECT md4,aich FROM known_files').fetchone()==(b'',b'')
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    assert not job.output_manifest.with_name(job.output_manifest.name+'-wal').exists()


def test_exchange_failure_preserves_previous_export(tmp_path):
    job,config=job_fixture(tmp_path)
    write_exchange(job)
    before=job.output_manifest.read_bytes()
    (config/'known2_64.met').write_bytes(b'\x02truncated')
    with pytest.raises(ValueError,match='truncated'):
        write_exchange(job)
    assert job.output_manifest.read_bytes()==before
    assert list(tmp_path.glob('profile-exchange-*.tmp'))==[]


def test_exchange_streams_100k_aliases_with_bounded_python_memory(tmp_path,monkeypatch):
    job,config=job_fixture(tmp_path)
    entry=known.parse_known_met(config/'known.met')[0]
    monkeypatch.setattr(known,'iter_known_met',lambda path:(replace(entry,name=f'Sample {i}.bin') for i in range(100_001)))
    tracemalloc.start()
    try:
        result=write_exchange(job,hashes_only=True)
        _,peak=tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result['summary']['knownRecords']==100_001
    assert peak<32*1024*1024
    with closing(sqlite3.connect(job.output_manifest)) as db:
        assert db.execute('SELECT count(*) FROM known_files').fetchone()[0]==100_001
