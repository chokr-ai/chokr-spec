import json
import shutil

import pytest

from chokr_spec import __version__, data_dir
from chokr_spec.runner import LEVELS, Report, Result, _subset, run


def test_every_packaged_vector_passes():
    for level in LEVELS:
        report = run(level)
        assert report.ok, [r for r in report.results if r.status != "pass"]
        assert report.failed == report.skipped == 0


def test_a_higher_level_includes_the_lower_ones():
    assert run("connect").passed > run("core").passed


def test_the_report_shape():
    wire = run("core").to_dict()
    assert wire["schema_version"] == "1.0"
    assert wire["spec_version"] == wire["version"] == __version__
    assert wire["level"] == "core"
    assert wire["passed"] == len(wire["results"]) and wire["failed"] == 0 and wire["skipped"] == 0
    assert all(set(r) == {"id", "status"} for r in wire["results"])


def test_an_unknown_level_is_refused():
    with pytest.raises(ValueError):
        run("service")


def test_a_result_shows_its_detail_only_when_it_has_one():
    assert Result("a", "fail", "why").to_dict() == {"id": "a", "status": "fail", "detail": "why"}


def test_an_empty_report_is_not_ok():
    assert not Report("core").ok
    assert not Report("core", results=[Result("a", "pass"), Result("b", "skip")]).ok


def test_a_folder_without_vectors_fails(tmp_path):
    report = run("core", vectors=tmp_path)
    assert not report.ok
    assert report.results[0].status == "fail" and "no vectors" in (report.results[0].detail or "")


def test_an_area_without_files_fails(data_copy):
    area = data_copy / "vectors" / "core" / "version"
    for path in area.glob("*.json"):
        path.unlink()
    report = run("core", vectors=data_copy / "vectors")
    assert any(r.id == "core/version" and r.status == "fail" for r in report.results)


def test_an_area_without_an_executor_fails(data_copy):
    area = data_copy / "vectors" / "core" / "mystery"
    area.mkdir()
    (area / "one.json").write_text(json.dumps({"id": "mystery/one", "expected": {}}), encoding="utf-8")
    report = run("core", vectors=data_copy / "vectors")
    failed = [r for r in report.results if r.status == "fail"]
    assert [r.id for r in failed] == ["mystery/one"] and "no executor" in (failed[0].detail or "")


def test_a_wrong_expectation_fails(data_copy):
    path = data_copy / "vectors" / "core" / "version" / "same.json"
    vector = json.loads(path.read_text("utf-8"))
    vector["expected"]["accepted"] = False
    path.write_text(json.dumps(vector), encoding="utf-8")
    report = run("core", vectors=data_copy / "vectors")
    failed = [r for r in report.results if r.status == "fail"]
    assert [r.id for r in failed] == ["version/same"] and "expected" in (failed[0].detail or "")


def test_a_vector_that_cannot_run_fails(data_copy):
    (data_copy / "vectors" / "core" / "version" / "broken.json").write_text("{", encoding="utf-8")
    report = run("core", vectors=data_copy / "vectors")
    failed = [r for r in report.results if r.status == "fail"]
    assert len(failed) == 1 and failed[0].detail == "JSONDecodeError"


def test_the_data_is_where_data_dir_says():
    root = data_dir()
    assert all((root / name).is_dir() for name in ("schemas", "registry", "vectors"))


def test_an_installed_copy_is_found_next_to_the_package(tmp_path, monkeypatch):
    import chokr_spec

    package = tmp_path / "chokr_spec"
    package.mkdir()
    (package / "data").mkdir()
    shutil.copy(chokr_spec.__file__, package / "__init__.py")
    monkeypatch.setattr(chokr_spec, "__file__", str(package / "__init__.py"))
    assert chokr_spec.data_dir() == package / "data"


def test_a_boolean_never_equals_a_number():
    assert not _subset({"ok": True}, {"ok": 1})
    assert not _subset({"n": 1}, {"n": True})
    assert _subset({"ok": True}, {"ok": True, "extra": 1})


def test_a_vector_without_an_expected_value_fails(data_copy):
    path = data_copy / "vectors" / "core" / "version" / "same.json"
    vector = json.loads(path.read_text("utf-8"))
    del vector["expected"]
    path.write_text(json.dumps(vector), encoding="utf-8")
    failed = [r for r in run("core", vectors=data_copy / "vectors").results if r.status == "fail"]
    assert [r.id for r in failed] == ["version/same"]


def test_a_tamper_vector_must_name_the_exact_error_and_place(data_copy):
    path = data_copy / "vectors" / "core" / "tamper" / "hash_altered.json"
    vector = json.loads(path.read_text("utf-8"))
    vector["expected_seq"] = 5
    path.write_text(json.dumps(vector), encoding="utf-8")
    failed = [r for r in run("core", vectors=data_copy / "vectors").results if r.status == "fail"]
    assert [r.id for r in failed] == ["tamper/hash_altered"]
    vector["expected_seq"], vector["expected_error"] = 1, "hash"
    path.write_text(json.dumps(vector), encoding="utf-8")
    assert [r.id for r in run("core", vectors=data_copy / "vectors").results if r.status == "fail"] == [
        "tamper/hash_altered"
    ]
