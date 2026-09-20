# Decisions

Tradeoffs worth explaining, and the reasoning behind them.

## PASS / FAIL / WARN, not pass/fail

A scanner that reports a machine as compliant when it simply could not read the setting
is worse than no scanner. It produces false confidence and hides the gap. Every path
that cannot reach a verdict resolves to WARN:

- The host was unreachable
- The account lacked rights to read the setting
- The value could not be parsed
- The matcher was not recognized
- The control has no correct fixed baseline (SUID inventory, local Administrators)

The connection layer keeps a distinct "could not execute" signal separate from "ran and
found nothing", because those mean different things. A missing file is a finding; an
unreadable one is not.

This came out of reading a reference tool that returned `True, "no condition recognized"`
for anything it did not understand.

## Score and coverage travel together

Excluding WARNs from the score is correct. An unverified control is not a failure. But
that alone lets a scan of two verified controls report 100%.

So coverage is always attached: `100% (verified 6/9 scored controls)` states a different
thing from `100% (verified 9/9)`, and the CLI, the HTML report, and the dashboard all
show it. When a before/after delta spans a coverage change, the comparison is flagged as
not like-for-like rather than presented as a real gain.

## The scanning account cannot remediate

Least privilege applies to the tool itself, not just to what it inspects.

- **Windows:** member of Remote Management Users, not Administrators
- **Linux:** sudo on four fixed helper verbs, no wildcards, no `NOPASSWD: ALL`

The sudoers entries carry no wildcards deliberately. A wildcarded `sudo find` entry
accepts `-exec`, which hands out a root shell and undoes the whole point.

The consequence is that `--apply` needs different credentials than a scan. That is the
intended shape: if the identity that reads the system could also change it, the
separation would be decorative.

## Elevation fails closed

Some controls genuinely need root. `/etc/sudoers` is mode 0440 and `/etc/ssh/sshd_config`
is 0600 on RHEL 9. Those run through a root-owned helper script exposing fixed verbs.

The helper prints nothing when it cannot run. An earlier shape piped through `wc -l`,
which turned a permission error into `0` and made the sudoers audit impossible to fail.
Printing nothing produces WARN instead, which is the honest answer.

Three Windows controls (`secedit`, `auditpol /get`, `Get-HotFix`) have no unprivileged
equivalent at all and report WARN permanently. The production answer there is JEA: a
constrained endpoint exposing exactly those commands. Same pattern as the Linux helper,
not yet built.

## Ansible remediates both platforms

Detection and reporting stay in Python because the control-by-control logic is the point
of the project. Every change goes through Ansible, on both platforms, because
idempotency, check-mode, and safe config-file editing are already solved there.

`--dry-run` maps to Ansible's own `--check` rather than a Python imitation of it. One
invocation per run, scoped by tag to the controls the scan just found failing, never a
blanket apply, which would touch controls that already pass.

## What the tool refuses to fix

Three categories, all reported rather than skipped silently:

- **No safe automated fix**, enabling BitLocker on a running instance
- **Fixing it would break access**, stripping `NOPASSWD: ALL` from the admin account
  Ansible itself connects with
- **No correct baseline**, a blanket `chmod -R o-w` across a filesystem is precisely
  the reckless move that breaks production

A scan finding nine failures and planning eight is a lie by omission unless it names the
ninth. The CLI prints a `[NO FIX]` line for each.

## Waivers expire

Without documented risk acceptance, a compliance tool produces alert fatigue and people
stop reading it. With unbounded acceptance, findings disappear quietly.

- Expiry is mandatory; entries without a valid date are rejected and reported
- Only a FAIL can be waived, accepting a risk nobody measured is not risk acceptance
- A waived finding leaves the score but stays in the report, with owner and ticket
- Waived controls are never remediated, since that would overrule the decision

## Control IDs are not citations

`WIN-SMB1`, not `WIN-18.4.3`. CIS renumbers between releases, RHEL 9 moved its entire
file-permissions block from `6.1.x` to `7.1.x` between v1 and v2, and Windows Server 2022
has had five major benchmark versions. An identifier that doubles as a citation is wrong
the next time the benchmark ships.

The section lives in each rule's `references`, pinned to a version. Four controls have no
CIS equivalent and say so rather than borrowing a plausible-looking number.

NIST tags are mapped by control intent rather than lifted from a published crosswalk. The
families match the ones CIS uses for the same controls, but they are informed mappings,
not authoritative ones.

## Host-side date math

Patch recency is computed on the target and returned as an integer age. Comparing dates
in the scanner would couple results to the scanner's clock and would rot recorded test
fixtures as they aged.

## Fixtures are generated from the rules

Recorded command output is keyed on the exact probe the executor emits, and regenerated
from the rule files. CI fails if they drift.

Hand-written fixtures encode the same assumptions as the code they test, so they agree
with each other while both are wrong. Live testing found roughly a dozen bugs the
fixtures could not, a false PASS on a running service the scanner could not see, a
`grep -c` exit code treated as failure, unreadable files reported as violations.
