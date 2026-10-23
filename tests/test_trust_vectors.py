"""The trust vectors as a set: the generator reproduces them, the coverage lint guards them, the plugin protocol is whole."""

import json
import shutil
import sys

import pytest
from tools import check_spec, gen_trust_vectors

from chokr_spec import data_dir
from chokr_spec.cli import main
from chokr_spec.runner import LEVELS, run


def problems(root) -> str:
    return "\n".join(check_spec.check(root))


def test_the_trust_level_is_the_highest_and_includes_the_others():
    assert LEVELS[-1] == "trust"
    assert run("trust").passed > run("connect").passed > run("core").passed


def test_every_trust_vector_passes():
    report = run("trust")
    assert report.ok and report.failed == 0, [r for r in report.results if r.status != "pass"]


def test_the_cli_runs_the_trust_level(capsys):
    assert main(["check", "--level", "trust"]) == 0
    assert "0 failed" in capsys.readouterr().out


def test_the_generator_reproduces_the_committed_vectors(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["gen_trust_vectors", "--check"])
    assert gen_trust_vectors.main() == 0


def test_the_generator_notices_a_vector_that_changed(monkeypatch, tmp_path, capsys):
    copy = tmp_path / "trust"
    shutil.copytree(data_dir() / "vectors" / "trust", copy)
    path = copy / "credential" / "valid.json"
    path.write_text(path.read_text("utf-8").replace('"cred-1"', '"cred-2"'), encoding="utf-8")
    monkeypatch.setattr(gen_trust_vectors, "ROOT", copy)
    monkeypatch.setattr(sys, "argv", ["gen_trust_vectors", "--check"])
    assert gen_trust_vectors.main() == 1
    assert "credential/valid" in capsys.readouterr().err


def test_the_generator_stops_when_the_checker_disagrees_with_a_stated_result():
    vector = {"id": "x"}
    with pytest.raises(SystemExit, match="expected"):
        gen_trust_vectors.write(
            "thumbprint",
            "never_written",
            "valid",
            "wrong on purpose",
            {"jwk": gen_trust_vectors.KEYS["acme"].jwk},
            {"thumbprint": "sha256:no"},
        )
    assert vector and "thumbprint/never_written" not in gen_trust_vectors.written


def test_the_main_check_lists_the_vectors_of_every_area(capsys):
    assert check_spec.main() == 0
    out = capsys.readouterr().out
    for area in check_spec.TRUST_AREAS:
        assert f"trust/{area}:" in out


def test_an_area_without_a_tamper_vector_is_named(data_copy):
    for path in (data_copy / "vectors" / "trust" / "passport").glob("*.json"):
        if json.loads(path.read_text("utf-8"))["class"] == "tamper":
            path.unlink()
    assert "vectors/trust/passport: no tamper vector" in problems(data_copy)


def test_an_area_without_a_valid_vector_is_named(data_copy):
    for path in (data_copy / "vectors" / "trust" / "thumbprint").glob("*.json"):
        path.unlink()
    text = problems(data_copy)
    assert "vectors/trust/thumbprint: no valid vector" in text


def test_a_vector_with_an_unknown_class_is_named(data_copy):
    path = data_copy / "vectors" / "trust" / "thumbprint" / "p256.json"
    vector = json.loads(path.read_text("utf-8"))
    vector["class"] = "positive"
    path.write_text(json.dumps(vector), encoding="utf-8")
    assert "class 'positive' is not one of valid, invalid, tamper" in problems(data_copy)


def test_an_unknown_trust_area_is_named(data_copy):
    area = data_copy / "vectors" / "trust" / "mystery"
    area.mkdir()
    (area / "one.json").write_text(
        json.dumps({"id": "mystery/one", "level": "trust", "class": "valid"}), encoding="utf-8"
    )
    assert "vectors/trust/mystery: not a known trust area" in problems(data_copy)


def test_an_unreadable_trust_vector_does_not_stop_the_lint(data_copy):
    (data_copy / "vectors" / "trust" / "pop" / "broken.json").write_text("[", encoding="utf-8")
    assert "pop/broken.json: not valid JSON" in problems(data_copy)


def test_the_plugin_protocol_must_be_whole(data_copy):
    path = data_copy / "proto" / "service_plugin.proto"
    text = path.read_text("utf-8")
    path.write_text(text.replace("service Guard {", "service Watcher {").replace("proto3", "proto2"), encoding="utf-8")
    found = problems(data_copy)
    assert "is not proto3" in found and "no service Guard" in found
    path.write_text(text.replace("package chokr.service_plugin.v1;", "package other;"), encoding="utf-8")
    assert "package is not chokr.service_plugin.v1" in problems(data_copy)
    path.unlink()
    assert "proto/service_plugin.proto: missing" in problems(data_copy)


def test_the_plugin_protocol_names_the_authentication_it_expects():
    text = (data_dir() / "proto" / "service_plugin.proto").read_text("utf-8")
    for word in ("chokr-ext+jwt", "EdDSA", "caller_kind", "expected_audience", "required_capabilities"):
        assert word in text
