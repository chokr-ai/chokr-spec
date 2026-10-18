# chokr-spec: the CHOKR protocol for AI agent governance (JSON Schemas, registries, conformance vectors)

[![PyPI](https://img.shields.io/pypi/v/chokr-spec)](https://pypi.org/project/chokr-spec/)
[![Python](https://img.shields.io/pypi/pyversions/chokr-spec)](https://pypi.org/project/chokr-spec/)
[![CI](https://github.com/chokr-ai/chokr-spec/actions/workflows/ci.yml/badge.svg)](https://github.com/chokr-ai/chokr-spec/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/chokr-spec)](https://github.com/chokr-ai/chokr-spec/blob/main/LICENSE)

The CHOKR protocol as data: JSON Schemas for the documents that govern AI agents (envelope, signed verdict, tamper-evident
audit ledger, approval, pack, plugin manifest and config), registries of standard names, and conformance vectors. The
package also holds a reference checker that runs the vectors, so any implementation, in any language, can compare its
results with the same inputs.

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

`data_dir()` is the folder that holds `schemas/`, `registry/` and `vectors/`. Another implementation can load the same
files and reproduce every vector's `expected` value.

## What is inside

```text
schemas/    JSON Schemas of the documents: envelope, signal, verdict, ledger record, approval, budget event,
            pack, plugin manifest, config and action mappings
registry/   names CHOKR defines: kinds, signal codes, reason codes, evidence types, obligation types, error codes
vectors/    core/ and connect/ conformance vectors, one folder per area
src/        the reference checker and the `chokr-spec` command
tools/      gen_vectors.py rewrites the vectors that need only a hash function; check_spec.py checks all the data
```

A vector is a JSON file with an `id`, a `level`, an `input` and an `expected` result. The `id` is `<area>/<file name>` and
the `level` is the folder it sits in. The areas are `envelope` (canonical form and digest), `ledger` (the hash chain),
`tamper` (a changed chain), `schema` (a document against a schema), `version` (version compatibility) and `verdict`
(signature verification). The levels are `core` and `connect`; a `trust` level is reserved and has no vectors yet.

## What is normative

The JSON Schemas, the registries and the vectors define the protocol. The Python checker is a reference implementation
of the vectors, not a second source of truth. When they disagree, the vectors win and the checker is wrong.

- Each schema describes one minor version exactly. Inside that version an unknown field is invalid, and `ext` is the
  place for extensions. A reader that supports `1.m` accepts documents from `1.0` to `1.m`, each against its own schema.
- Patterns in the schemas must match the whole text, and a trailing newline never matches.
- Signatures are strict unpadded base64url, and the checks run in a fixed order: unsigned, malformed signature, kid not
  allowed, unknown kid, algorithm, then the signature itself. A kid that is both unknown and not allowed is reported as
  not allowed.
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
