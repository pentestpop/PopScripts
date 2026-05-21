#!/usr/bin/env python3
"""
burp2hydra.py - Convert a raw Burp HTTP request into a Hydra command.
Paste your Burp request, answer a few prompts, get your command.
"""

import sys
import re
from urllib.parse import urlparse


# ── ANSI colours (degrade gracefully on Windows) ─────────────────────────────
try:
    import os
    if os.name == "nt":
        raise ImportError
    BOLD  = "\033[1m"
    CYAN  = "\033[96m"
    GREEN = "\033[92m"
    YELLOW= "\033[93m"
    RESET = "\033[0m"
except ImportError:
    BOLD = CYAN = GREEN = YELLOW = RESET = ""


def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════╗
║         burp  →  hydra  builder      ║
╚══════════════════════════════════════╝{RESET}
Paste your raw Burp request below.
When done, enter a line with just {BOLD}END{RESET} (or Ctrl-D / Ctrl-Z).
""")


# ── Request parsing ───────────────────────────────────────────────────────────

def read_raw_request() -> str:
    lines = []
    print(f"{YELLOW}>> Paste request (then END):{RESET}")
    for line in sys.stdin:
        stripped = line.rstrip("\n")
        if stripped.strip().upper() == "END":
            break
        lines.append(stripped)
    return "\n".join(lines)


def parse_request(raw: str) -> dict:
    """Return a dict with method, path, host, port, https, headers, body."""
    lines = raw.splitlines()
    if not lines:
        sys.exit("No request data found.")

    # Request line
    parts = lines[0].split()
    if len(parts) < 2:
        sys.exit(f"Cannot parse request line: {lines[0]!r}")
    method = parts[0].upper()
    path   = parts[1]

    # Headers
    headers = {}
    body_start = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    body = "\n".join(lines[body_start:]).strip() if body_start else ""

    host_header = headers.get("host", "")
    # host may include port  e.g.  example.com:8443
    if ":" in host_header:
        host, port_str = host_header.rsplit(":", 1)
        port = int(port_str)
    else:
        host = host_header
        port = None

    return {
        "method":  method,
        "path":    path,
        "host":    host,
        "port":    port,
        "headers": headers,
        "body":    body,
    }


# ── Interactive prompts ───────────────────────────────────────────────────────

def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{CYAN}{prompt}{suffix}:{RESET} ").strip()
    return val if val else default


def choose(prompt: str, options: list, default: str = "") -> str:
    opts_str = "/".join(options)
    suffix   = f" [{default}]" if default else f" ({opts_str})"
    while True:
        val = input(f"{CYAN}{prompt}{suffix}:{RESET} ").strip().lower()
        if not val and default:
            return default
        if val in [o.lower() for o in options]:
            return val
        print(f"  Please choose one of: {opts_str}")


def collect_params(parsed: dict) -> dict:
    """Ask the user for everything Hydra needs that can't be auto-detected."""
    print(f"\n{BOLD}── Target ──────────────────────────────{RESET}")

    # HTTPS detection heuristic
    https_default = "y" if parsed["port"] in (443, 8443) else "n"
    use_https = choose("Use HTTPS?", ["y", "n"], default=https_default) == "y"

    port = parsed["port"]
    if port is None:
        port_input = ask("Port (leave blank for default 80/443)", "")
        port = int(port_input) if port_input else None

    print(f"\n{BOLD}── Credentials ─────────────────────────{RESET}")
    cred_mode = choose(
        "Single username or list?",
        ["single", "list"],
        default="single",
    )
    if cred_mode == "single":
        username = ask("Username")
        username_flag = f"-l {username}"
    else:
        ulist = ask("Path to username list", "/usr/share/wordlists/users.txt")
        username_flag = f"-L {ulist}"

    pass_mode = choose(
        "Single password or list?",
        ["single", "list"],
        default="list",
    )
    if pass_mode == "single":
        password = ask("Password")
        password_flag = f"-p {password}"
    else:
        plist = ask("Path to password list", "/usr/share/wordlists/rockyou.txt")
        password_flag = f"-P {plist}"

    print(f"\n{BOLD}── Form fields ─────────────────────────{RESET}")
    body = parsed["body"]

    # Try to auto-detect user/pass fields
    user_field = _guess_field(body, ["user", "username", "email", "login", "uname"])
    pass_field  = _guess_field(body, ["pass", "password", "passwd", "pwd", "secret"])

    if user_field:
        print(f"  Detected username field: {YELLOW}{user_field}{RESET}")
    user_field = ask("Username field name", default=user_field or "username")

    if pass_field:
        print(f"  Detected password field: {YELLOW}{pass_field}{RESET}")
    pass_field = ask("Password field name", default=pass_field or "password")

    print(f"\n{BOLD}── Response detection ──────────────────{RESET}")
    print("  Hydra needs to know what a FAILED login looks like (or a SUCCESS).")
    detection = choose("Use failure string or success string?", ["failure", "success"], default="failure")
    det_string = ask(f"{'Failure' if detection == 'failure' else 'Success'} string")
    det_prefix = "F=" if detection == "failure" else "S="

    print(f"\n{BOLD}── Extra headers / cookies? ────────────{RESET}")
    extra_headers = []
    while True:
        h = ask("Add a header (e.g.  Cookie: session=abc)  or blank to skip", "")
        if not h:
            break
        extra_headers.append(h)

    print(f"\n{BOLD}── Performance ─────────────────────────{RESET}")
    threads = ask("Threads (-t)", default="16")

    verbose = choose("Verbose output (-V)?", ["y", "n"], default="n") == "y"

    return {
        "use_https":      use_https,
        "port":           port,
        "username_flag":  username_flag,
        "password_flag":  password_flag,
        "user_field":     user_field,
        "pass_field":     pass_field,
        "det_prefix":     det_prefix,
        "det_string":     det_string,
        "extra_headers":  extra_headers,
        "threads":        threads,
        "verbose":        verbose,
    }


def _guess_field(body: str, candidates: list) -> str:
    """Try to find a form field name matching any candidate keyword."""
    for pair in body.split("&"):
        if "=" in pair:
            key = pair.split("=", 1)[0].lower()
            for c in candidates:
                if c in key:
                    return pair.split("=", 1)[0]   # original case
    return ""


# ── Command builder ───────────────────────────────────────────────────────────

def build_command(parsed: dict, params: dict) -> str:
    host   = parsed["host"]
    path   = parsed["path"]
    method = parsed["method"]
    body   = parsed["body"]

    # Hydra module
    proto = "https" if params["use_https"] else "http"
    if method == "GET":
        module = f"{proto}-get-form"
    else:
        module = f"{proto}-post-form"

    # Replace credential values in the body with ^USER^ / ^PASS^
    def replace_field(text, field, marker):
        # handles  field=anything  (value may be empty)
        return re.sub(
            rf"(?<=[&?]|^){re.escape(field)}=[^&]*",
            f"{field}={marker}",
            text,
        )

    form_body = body
    # Prepend & so the regex start-of-string anchor works uniformly
    sentinel = "&" + form_body
    sentinel = replace_field(sentinel, params["user_field"], "^USER^")
    sentinel = replace_field(sentinel, params["pass_field"], "^PASS^")
    form_body = sentinel.lstrip("&")

    # Extra header flags
    header_flags = "".join(f":H={h}" for h in params["extra_headers"])

    form_string = f"{path}:{form_body}:{params['det_prefix']}{params['det_string']}{header_flags}"

    # Assemble
    parts = ["hydra"]
    parts.append(params["username_flag"])
    parts.append(params["password_flag"])
    parts.append(f"-t {params['threads']}")
    if params["verbose"]:
        parts.append("-V")
    if params["port"]:
        parts.append(f"-s {params['port']}")
    parts.append(host)
    parts.append(module)
    parts.append(f'"{form_string}"')

    return " ".join(parts)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    banner()
    raw     = read_raw_request()
    parsed  = parse_request(raw)

    print(f"\n{GREEN}✔ Parsed:{RESET}  {parsed['method']} {parsed['host']}{parsed['path']}")
    if parsed["body"]:
        print(f"  Body:    {parsed['body'][:120]}{'…' if len(parsed['body']) > 120 else ''}")

    params  = collect_params(parsed)
    command = build_command(parsed, params)

    print(f"\n{BOLD}{GREEN}── Generated Hydra command ─────────────{RESET}")
    print(f"\n  {YELLOW}{command}{RESET}\n")
    print(f"{BOLD}(Command printed only — not executed){RESET}\n")


if __name__ == "__main__":
    main()
