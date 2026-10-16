import json
import subprocess
import sys

import pytest

from chokr_spec import __version__
from chokr_spec.cli import main


def test_check_passes_on_the_packaged_vectors(capsys):
    assert main(["check"]) == 0
    assert capsys.readouterr().out.strip().endswith("0 failed")


def test_the_level_can_be_chosen(capsys):
    assert main(["check", "--level", "core"]) == 0
    assert "passed" in capsys.readouterr().out


def test_json_output_and_report_file(tmp_path, capsys):
    report = tmp_path / "report.json"
    assert main(["check", "--json", "--report", str(report)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == json.loads(report.read_text("utf-8")) and printed["failed"] == 0


def test_a_failing_vector_sets_the_exit_code_and_is_named(data_copy, capsys):
    path = data_copy / "vectors" / "core" / "version" / "same.json"
    vector = json.loads(path.read_text("utf-8"))
    vector["expected"]["accepted"] = False
    path.write_text(json.dumps(vector), encoding="utf-8")
    assert main(["check", "--vectors", str(data_copy / "vectors")]) == 1
    out = capsys.readouterr().out
    assert "FAIL version/same" in out and "1 failed" in out


def test_version(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == f"chokr-spec {__version__}"


def test_a_command_is_required():
    with pytest.raises(SystemExit) as caught:
        main([])
    assert caught.value.code == 2


def test_the_module_runs_as_a_command():
    done = subprocess.run([sys.executable, "-m", "chokr_spec", "check"], capture_output=True, text=True, check=False)
    assert done.returncode == 0 and "0 failed" in done.stdout
