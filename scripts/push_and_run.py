#!/usr/bin/env python3
"""Copy a PowerShell script to a Windows host over WinRM and run it there.

WinRM encodes an inline script into the command line, which overflows once the
script grows past a couple of kilobytes. Uploading in chunks and executing from
disk avoids that ceiling and keeps the bootstrap runnable without RDP.

    python scripts/push_and_run.py <host> <script.ps1> [args...]

Credentials come from WINRM_USER / WINRM_PASS.
"""
from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

CHUNK = 1800  # base64 chars per round trip, well inside the command-line limit


def push_and_run(host, script_path, arg_prelude="", insecure=True):
    """arg_prelude is appended to the invocation, e.g. '-OperatorCidr 1.2.3.4/32'."""
    import winrm

    session = winrm.Session(
        f"https://{host}:5986/wsman",
        auth=(os.environ["WINRM_USER"], os.environ["WINRM_PASS"]),
        transport="ntlm",
        server_cert_validation="ignore" if insecure else "validate",
    )

    # arguments are passed to the script's own param() block rather than
    # prepended, because param() must be the first statement in a script
    body = Path(script_path).read_text()
    encoded = base64.b64encode(body.encode("utf-8")).decode()

    # literal path: a single-quoted $env:TEMP would not expand on the far side
    remote = r"C:\Windows\Temp\hardening_bootstrap.ps1"
    session.run_ps(f"Remove-Item -Path '{remote}.b64' -ErrorAction SilentlyContinue")
    for i in range(0, len(encoded), CHUNK):
        part = encoded[i : i + CHUNK]
        # no -NoNewline: it isn't available on every PowerShell build, so the
        # line breaks are simply stripped back out before decoding
        r = session.run_ps(f"Add-Content -Path '{remote}.b64' -Value '{part}'")
        if r.status_code != 0:
            return r.status_code, "", r.std_err.decode()

    decode = (
        f"$b64 = (Get-Content '{remote}.b64' -Raw) -replace '\\s',''; "
        f"[IO.File]::WriteAllText('{remote}', "
        f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)))"
    )
    r = session.run_ps(decode)
    if r.status_code != 0:
        return r.status_code, "", r.std_err.decode()

    r = session.run_ps(f"& '{remote}' {arg_prelude}")
    return r.status_code, r.std_out.decode(), r.std_err.decode()


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    host, script = sys.argv[1], sys.argv[2]
    prelude = sys.argv[3] if len(sys.argv) > 3 else ""
    code, out, err = push_and_run(host, script, prelude)
    if out.strip():
        print(out)
    if err.strip():
        print("STDERR:", err[-1200:], file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
