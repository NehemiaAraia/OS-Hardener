# Demo recording script

Target length **2:30**. Recorded in advance with OBS, not run live.

The single strongest moment is the score moving with a named list of what
changed. Everything else exists to set that up, so don't spend time elsewhere.

---

## Before you hit record

- [ ] Both instances running; RDP and SSH already connected
- [ ] Both hosts reset to a failing baseline (`scripts/lab_reset_*.sh`)
- [ ] One full unrecorded practice run
- [ ] `reports/` cleared of debugging noise
- [ ] Editor open on `scanner/` with the module list visible
- [ ] Terminal font large enough to read when shared small
- [ ] A *known good* first scan already captured, in case a live take misbehaves

Pre-stage the commands in shell history (press ↑ rather than typing) so there's
no dead air while you type.

---

## Shot 1 — what this is (0:00–0:20)

Editor showing `scanner/`.

> "This is a hardening and compliance tool for Windows Server and RHEL. One
> Python codebase scans both, scores them against CIS controls, tags findings to
> NIST 800-53, and remediates what it finds. The pipeline is parser, executor,
> evaluator, scoring, reporter — the platform only changes which rules load and
> which connection library is used."

Don't read the code. Twenty seconds, establish it's real, move on.

---

## Shot 2 — scan the unhardened host (0:20–0:50)

```bash
python main.py scan --target linux --host <linux-ip>
```

Let the control list stream. While it runs:

> "It's connecting over SSH as a dedicated service account — not root. That
> account's sudo access is three fixed read-only commands, so the scanner can't
> change anything it's looking at."

When the summary lands:

> "Thirty percent. Ten of eleven scored controls verified — the one it couldn't
> verify is reported as WARN, not passed. That's deliberate: this tool never
> defaults to PASS on something it couldn't check."

**That last sentence is the most important thing you say.** It's the difference
between a script that prints green ticks and a tool someone would trust.

---

## Shot 3 — the report (0:50–1:20)

Open the generated HTML.

> "Same data as a report. Score, pass/fail/warn counts, and every control
> expands to show the evidence it collected, the CIS level, and the NIST
> control it maps to."

Expand **one** FAIL — root SSH login is a good one — and point at the NIST tag.

If a waiver is in play, expand it:

> "This one's a documented exception — owner, ticket, expiry. It's out of the
> score but still on the report. And waivers expire, so an accepted risk can't
> quietly become a forgotten one."

---

## Shot 4 — dry run (1:20–1:40)

```bash
python main.py remediate --target linux --host <linux-ip> --dry-run
```

> "Dry run is the default. It rescans first, so it only acts on what's actually
> failing right now — and never on a WARN, because acting on a control you
> couldn't verify is how you break a working machine."

---

## Shot 5 — apply (1:40–2:00)

```bash
python main.py remediate --target linux --host <linux-ip> --apply
```

Confirmation prompt appears. Pause on it for a beat before typing `y`.

> "Applying needs an explicit confirm — and different credentials. The scanning
> account is read-only by design, so it can't remediate. In a real environment
> this step carries a change ticket."

As Ansible's output streams:

> "Linux remediation runs through an Ansible playbook. Idempotency and check
> mode are already solved there, so Python does detection and reporting and
> Ansible does the changes."

---

## Shot 6 — the payoff (2:00–2:30)

```bash
python main.py scan --target linux --host <linux-ip>
```

Say nothing until the delta block renders. Let it land.

> "Thirty to a hundred. And it's not just a number — it lists every control that
> moved, by ID. Anything that regressed would show up here too, flagged."

Point at any `(unchanged)` line:

> "This one didn't change — no safe automated fix, so it's flagged for manual
> action instead of being quietly skipped."

Close:

> "Same tool, same two commands, against Windows over WinRM."

---

## If a take goes wrong

- **A control WARNs unexpectedly** — leave it in and explain it. A tool that
  admits what it couldn't verify is the whole argument. Don't re-record.
- **Ansible fails a task** — stop, fix, re-record. A failed apply undercuts it.
- **The delta doesn't render** — the previous scan wasn't stored, or the host
  string differs between runs. Both scans must use the same `--host`.

---

## Windows variant

Same six shots. Two differences worth narrating:

- WinRM over **HTTPS on 5986**; the bootstrap deletes the 5985 cleartext
  listener. Mention this unprompted — it's a detail reviewers look for.
- Remediation is Python in-process rather than Ansible, and SMBv1 removal flags
  a reboot rather than forcing one.

If you only have time for one platform, record **Linux** — the Ansible output on
screen is more visually convincing than a Python function returning `done`.
