# chokr-spec: the CHOKR protocol for AI agent governance (JSON Schemas, registries, conformance vectors)

[![PyPI](https://img.shields.io/pypi/v/chokr-spec)](https://pypi.org/project/chokr-spec/)
[![Python](https://img.shields.io/pypi/pyversions/chokr-spec)](https://pypi.org/project/chokr-spec/)
[![CI](https://github.com/chokr-ai/chokr-spec/actions/workflows/ci.yml/badge.svg)](https://github.com/chokr-ai/chokr-spec/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/chokr-spec)](https://github.com/chokr-ai/chokr-spec/blob/main/LICENSE)

The CHOKR protocol as data: JSON Schemas for the documents that govern AI agents (envelope, signed verdict, tamper-evident
audit ledger, approval, pack, plugin manifest and config; and, for trust, the credential, delegation, evidence, passport,
proof of possession, authority epoch, execution grant and trust config), the protocol of out-of-process plugins,
registries of standard names, and conformance vectors. The package also holds a reference checker that runs the
vectors, so any implementation, in any language, can compare its results with the same inputs.

The policy language has its own repository, `chokr-policy-language`. Its outcomes, standard reason codes and authoring
error codes are defined there and are not repeated here.

## Install

```
pip install chokr-spec
```

Python 3.14 or newer. Import name: `chokr_spec`.

## Check the vectors

```console
$ chokr-spec check
$ chokr-spec check --level core --report report.json
```

`--level` is the highest level to run: `core`, `connect` or `trust`. A level includes the ones below it.

The command exits with `0` only when every vector passes. `--vectors DIR` runs a different folder of vectors, and
`--json` prints the report.

## Use from Python

```python
from chokr_spec import data_dir
from chokr_spec.runner import run

report = run("core")
print(report.passed, report.failed, report.ok)
print(data_dir() / "schemas")
```

`data_dir()` is the folder that holds `schemas/`, `registry/`, `vectors/` and `proto/`. Another implementation can load the same
files and reproduce every vector's `expected` value.

## What is inside

```text
schemas/    JSON Schemas of the documents: envelope, signal, verdict, ledger record, approval, budget event,
            pack, plugin manifest, config and action mappings; and manifest (`chokr.lock`), message contract,
            credential, delegation, evidence, passport, proof of possession, authority epoch, execution grant
            and trust config
proto/      service_plugin.proto: the protocol of out-of-process plugins (`chokr.service_plugin/1.0`)
registry/   names CHOKR defines: kinds, signal codes, reason codes, evidence types, obligation types, error codes
vectors/    core/, connect/ and trust/ conformance vectors, one folder per area
src/        the reference checker and the `chokr-spec` command
tools/      gen_vectors.py and gen_trust_vectors.py rewrite the vectors that are computed; check_spec.py checks all the
            data
```

A vector is a JSON file with an `id`, a `level`, an `input` and an `expected` result. The `id` is `<area>/<file name>` and
the `level` is the folder it sits in. The areas are `envelope` (canonical form and digest), `ledger` (the hash chain),
`tamper` (a changed chain), `schema` (a document against a schema), `version` (version compatibility) and `verdict`
(signature verification). The `trust` level has the areas `crypto` (four algorithm families and hybrid proofs), `jws`,
`thumbprint`, `credential`, `delegation` (attenuation), `evidence` (freshness), `passport`, `pop` (proof of possession,
replay), `keybinding`, `epoch` (rollback), `vc` (W3C Data Integrity `eddsa-jcs-2022` and `ecdsa-jcs-2019`, with the values
the W3C specifications publish) and `sdjwt` (disclosure digests). A trust vector also has a `class`: `valid`, `invalid`
or `tamper` (a signed document changed after it was signed), and `check_spec.py` fails when an area has no valid vector or
no tamper vector.

## What is normative

The JSON Schemas, the registries and the vectors define the protocol. The Python checker is a reference implementation
of the vectors, not a second source of truth. When they disagree, the vectors win and the checker is wrong.

- Each schema describes one minor version exactly. Inside that version an unknown field is invalid, and `ext` is the
  place for extensions. A reader that supports `1.m` accepts documents from `1.0` to `1.m`, each against its own schema.
- Patterns in the schemas must match the whole text, and a trailing newline never matches.
- Signatures are strict unpadded base64url, and the checks run in a fixed order: unsigned, malformed signature, kid not
  allowed, unknown kid, algorithm, then the signature itself. A kid that is both unknown and not allowed is reported as
  not allowed.
- Trust checks run in a fixed order too, and the first failing check gives the code: for a credential, the key owner, the
  signature, issuer trust, the validity window, the subject, the audience, then status. One clock tolerance (default 30 s,
  at most 300 s) applies to every time check, and a document is valid on `issued_at - tolerance <= now < expires_at +
  tolerance`. Verification uses the algorithm of the key; the algorithm a signature names is only compared with it.
- A ledger chain verifies from `seq` 0 and reports the first problem as `<class> at seq <n>`. A chain cut short at the
  end still verifies by itself, so a reader that must detect a cut keeps the head hash it last saw and passes it to
  `verify_chain(..., expected_head=...)`.

## Versioning

- The package version is the protocol version. Before 1.0 every change is a patch.
- A consumer accepts any minor version of its major version and ignores unknown `ext` names.
- Optional fields are omitted, never `null`, so digests stay stable.
- A published code never changes meaning.

## Contributing and security

See [CONTRIBUTING.md](https://github.com/chokr-ai/chokr-spec/blob/main/CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](https://github.com/chokr-ai/chokr-spec/blob/main/SECURITY.md), not in public issues.

## License

Apache License 2.0. Copyright 2026 chokr-ai. See [LICENSE](https://github.com/chokr-ai/chokr-spec/blob/main/LICENSE) and [NOTICE](https://github.com/chokr-ai/chokr-spec/blob/main/NOTICE).
