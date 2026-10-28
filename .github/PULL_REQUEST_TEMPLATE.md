<!--
Delete any section that genuinely does not apply, but keep the gate list.
-->

## What problem does this solve?

One or two sentences. If it fixes an issue, link it.

## Behaviour change?

Say so explicitly if any of these moved, and update `CHANGELOG.md` under
Unreleased:

- [ ] A packet that used to parse now raises (or the reverse)
- [ ] A TTL, cache, or negative-answer decision changed
- [ ] A public name changed (module, class, enum member, CLI flag)
- [ ] Nothing observable changed

A parser that starts rejecting input is a *feature* here if the input was
malformed — RFC 5625 section 6.3 permits dropping a broken message and does not
require tolerating it. But it must be a decision, not a surprise.

## Gates

These are the commands CI runs. Run them locally before pushing; the `-O` run is
the one that catches assertions carrying real validation, which is this codebase's
main historical failure mode.

```bash
pytest -q                      # coverage floor enforced by pyproject
python -O -m pytest -q
ruff check . && ruff format --check .
mypy namespy
```

- [ ] All four pass locally

## Spec

Which document and section required this? If the change *is* a spec question, the
reading you chose belongs in `docs/rfc-map.md` — that file exists so the next
person does not have to re-litigate it.

## Tests

Every parser change needs a byte-level test that pins the exact failure, not just
a round-trip. For a new rejection, name the condition in the test. For a new
acceptance, assert the decoded value, not merely that nothing raised.
