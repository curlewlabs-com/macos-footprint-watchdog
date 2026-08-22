# Contributing

Thanks for your interest in improving `macos-footprint-watchdog`. It is a
focused tool, so the bar for a change is "does this make it more reliable at
catching a runaway process and restarting it safely" - bug fixes, safety
hardening, support for another measurement the kernel actually exposes, and
clearer docs are all welcome.

## Before a large change

Open an issue describing the problem first. The signalling path carries the
safety invariants (exact path matching, ambiguity refusal, target
re-verification before the signal, the cooldown stamped before the outcome is
known), so a
short discussion up front saves rework.

## Running the checks

These are the same two checks CI runs on every push and PR:

```sh
/usr/bin/python3 -m unittest discover -s test -v   # macOS, needs cc
npx pyright@1.1.409                                # strict; runs anywhere
```

The test suite needs macOS: it compiles a target process and reads the real
kernel ledger. The type check runs anywhere - `pyrightconfig.json` pins
`pythonPlatform` to Darwin so the macOS-only calls resolve on Linux too.

## Conventions

- **Tests ship with the change.** A bug fix or feature includes a test in the
  same pull request. CI runs the suite on macOS, so you do not need a Mac to
  have your change verified - but you do need to add the test.
- **Prefer a real process over a mocked measurement.** The bugs worth catching
  here live at the boundary: what `proc_pidpath` reports, whether a signalled
  process is actually replaced, whether the ledger reflects an allocation. A
  test that mocks `read_sample` only asserts that this file agrees with
  itself.
- **No change-detector tests.** A test that pins a literal (the exact plist
  dict, an exact log string) fails on every legitimate edit while catching
  nothing. Test the invariant instead - for example, that the arguments the
  installer generates are arguments the watchdog's own parser accepts.
- **Pin dependencies exactly.** The `pyright` pin and the action pins in CI are
  exact versions so a resolver cannot silently move them. Match that when
  adding any.
- **Comments explain _why_, not _what_.** Most of the non-obvious code here is
  non-obvious for a reason that was measured (why not RSS, why not `vmmap`, why
  the mach timebase conversion is not optional). Keep the reason with the code.
- **Safe by default stays the default.** `--dry-run` signals nothing; anything
  new that can act on a process stays behind an explicit flag and the existing
  identity checks.

## Submitting

Keep each pull request focused on one change, make sure both checks pass, and
describe the _why_ in the PR body. CI must be green before merge.
