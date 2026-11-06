# Working rules for this repository

## Always commit and push

After finishing any change, commit it and push it to `origin main` without being
asked. Do not leave work uncommitted and do not ask whether to commit.

- one commit per logical change, message in the repo's existing style: a short
  imperative subject line, then a body that says *why* (what was broken, what the
  change does about it)
- `git add -A && git commit && git push origin main`
- never commit `test-harness/automation/.builds/` or `shots/` (gitignored)

## Diagnostics must stay secret-free

`src/log.js` is the only place that decides what may be stored. Any new log call
site passes shape, counts and decisions, never values:

- no password, pairing code, TOTP value, SRP material (`A`, `B`, `salt`, `M`,
  `sharedKey`), `SDATA`/`PAYLOAD`, URL query or fragment
- usernames go through `maskUser()` (or `opMask()` in the content script)
- run `npm test` after touching logging; it asserts the redaction contract

## Versioning

`manifest.json` `version` and `OP_BUILD` in `src/content.js` are bumped together
when behaviour changes, so an exported diagnostics file names the build it came
from.

## Tests

```bash
npm test                                   # log redaction + plain-HTTP fill guard self-tests
cd test-harness/automation
node build-test-extensions.mjs             # mock builds, no macOS helper needed
node run-all.mjs                           # needs playwright + a server on :8799
```

`checkout-address #email` in the adversarial suite fails on `HEAD` before any of
our changes (a "Continue to payment" button makes `loginishContext` true). It is
a known pre-existing false positive, not a regression.
