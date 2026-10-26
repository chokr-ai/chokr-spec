import json
import shutil

from tools import check_spec, gen_vectors

from chokr_spec import data_dir


def test_the_protocol_data_passes_every_check():
    assert check_spec.check(data_dir()) == []


def test_main_reports_ok(capsys):
    assert check_spec.main() == 0
    assert "ok" in capsys.readouterr().out


def test_main_lists_problems(monkeypatch, data_copy, capsys):
    (data_copy / "vectors" / "core" / "version" / "broken.json").write_text("{", encoding="utf-8")
    monkeypatch.setattr(check_spec, "data_dir", lambda: data_copy)
    assert check_spec.main() == 1
    assert "not valid JSON" in capsys.readouterr().err


def problems(root) -> str:
    return "\n".join(check_spec.check(root))


def test_a_schema_that_no_vector_uses_is_reported(data_copy):
    shutil.copy(data_copy / "schemas" / "pack.schema.json", data_copy / "schemas" / "extra.schema.json")
    text = problems(data_copy)
    assert "extra.schema.json: no vector uses this schema" in text and "$id is" in text


def test_a_schema_with_the_wrong_id_or_a_bad_definition_is_reported(data_copy):
    path = data_copy / "schemas" / "pack.schema.json"
    document = json.loads(path.read_text("utf-8"))
    document["$id"] = "https://example.test/pack"
    document["type"] = "nonsense"
    path.write_text(json.dumps(document), encoding="utf-8")
    text = problems(data_copy)
    assert "not a valid schema" in text and "$id is" in text


def test_vector_files_are_checked(data_copy):
    area = data_copy / "vectors" / "core" / "version"
    shutil.copy(area / "same.json", area / "again.json")
    (area / "no_id.json").write_text("{}", encoding="utf-8")
    (area / "list.json").write_text("[]", encoding="utf-8")
    text = problems(data_copy)
    assert "is also used by" in text and "no_id.json: no id" in text and "list.json: no id" in text


def test_an_area_without_an_executor_is_reported(data_copy):
    area = data_copy / "vectors" / "core" / "mystery"
    area.mkdir()
    (area / "one.json").write_text(json.dumps({"id": "mystery/one"}), encoding="utf-8")
    assert "no executor for the area 'mystery'" in problems(data_copy)


def test_registries_are_checked(data_copy):
    registry = data_copy / "registry"
    (registry / "kinds.yaml").write_text("schema_version: '2.0'\nentries: []\n", encoding="utf-8")
    (registry / "error_codes.yaml").write_text(
        "schema_version: '1.0'\nentries:\n- code: B\n- code: A\n- code: A\n", encoding="utf-8"
    )
    text = problems(data_copy)
    assert "schema_version is 1.0" in text and "no entries" in text
    assert "not sorted" in text and "appears twice" in text


def test_the_generated_vectors_match_the_committed_ones(tmp_path, monkeypatch):
    monkeypatch.setattr(gen_vectors, "ROOT", tmp_path / "core")
    gen_vectors.envelope_vectors()
    gen_vectors.anchor_vectors()
    gen_vectors.lockhash_vectors()
    gen_vectors.tamper_vectors(gen_vectors.ledger_vectors())
    gen_vectors.redacted_ledger_vector()
    gen_vectors.version_vectors()
    gen_vectors.verdict_vectors()
    gen_vectors.pattern_vectors()
    committed = data_dir() / "vectors"
    written = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*.json"))
    assert len(written) == 86
    for relative in written:
        assert (tmp_path / relative).read_bytes() == (committed / relative).read_bytes(), relative


def test_a_schema_must_be_strict_and_versioned(data_copy):
    path = data_copy / "schemas" / "pack.schema.json"
    document = json.loads(path.read_text("utf-8"))
    document["$schema"] = "https://json-schema.org/draft-07/schema"
    document["additionalProperties"] = True
    document["required"] = ["name"]
    path.write_text(json.dumps(document), encoding="utf-8")
    text = problems(data_copy)
    assert "is not Draft 2020-12" in text
    assert "allows unknown properties" in text
    assert "does not require schema_version or schema" in text


def test_a_vector_id_and_level_must_match_its_path(data_copy):
    path = data_copy / "vectors" / "core" / "version" / "same.json"
    vector = json.loads(path.read_text("utf-8"))
    vector["id"], vector["level"] = "version/other", "connect"
    path.write_text(json.dumps(vector), encoding="utf-8")
    text = problems(data_copy)
    assert "id is 'version/other'" in text and "level is 'connect'" in text
