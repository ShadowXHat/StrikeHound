#!/usr/bin/env python3
"""
StrikeHound ZAP environment check.

Verifies the parts of the ZAP integration that unit tests can only mock:
that a real ZAP daemon is reachable and that context + authentication
setup actually works against that version of ZAP.

Usage:
    python scripts/zap_env_check.py --url http://localhost:8080 --target https://example.com
    python scripts/zap_env_check.py --url http://localhost:8080 --target https://example.com \
        --username alice --password 's3cret' --login-url https://example.com/login

Exit code 0 = everything checked out, 1 = something failed.
"""
import argparse
import os
import sys

# Allow `python scripts/zap_env_check.py` to import the modules/ package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import requests

import modules.zap_scanner as zap_scanner

DEFAULT_CONTEXT = "strikehound-env-check"


def _report(ok: bool, message: str) -> bool:
    print(("[+] " if ok else "[!] ") + message)
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8080", help="ZAP daemon API base URL")
    parser.add_argument("--api-key", default="", help="ZAP API key if key auth is enabled")
    parser.add_argument("--target", default="http://example.com", help="URL to use for the check")
    parser.add_argument("--context-name", default=DEFAULT_CONTEXT)
    parser.add_argument("--login-url", default="", help="Required with --username/--password (form auth)")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    args = parser.parse_args()

    api_url = args.url.rstrip("/")
    base_params = {"apikey": args.api_key} if args.api_key else {}
    headers = {"Accept": "application/json"}
    all_ok = True

    # 1. Reachability + version
    if not zap_scanner.is_zap_ready(api_url):
        print(f"[!] ZAP is not reachable at {api_url}.")
        print("    Start it first, e.g.:  zap.sh -daemon -port 8080 -config api.disablekey=true")
        return 1
    try:
        r = requests.get(f"{api_url}/JSON/core/view/version/", params=base_params, headers=headers, timeout=10)
        version = r.json().get("version", "?")
        all_ok &= _report(True, f"ZAP reachable, version {version}")
    except (requests.exceptions.RequestException, ValueError):
        all_ok &= _report(False, "ZAP reached but version could not be read.")

    # 2. Context creation + scoping
    try:
        context_id = zap_scanner._new_context(api_url, base_params, headers, args.context_name)
        all_ok &= _report(True, f"Context '{args.context_name}' created (id {context_id})")
    except Exception as e:
        _report(False, f"Context creation failed: {e}")
        return 1

    try:
        zap_scanner._include_target_in_context(args.target, api_url, base_params, headers, args.context_name)
        all_ok &= _report(True, f"Context scoped to {args.target}")
    except Exception as e:
        all_ok &= _report(False, f"Context scoping failed: {e}")

    # 3. Form-auth setup (optional)
    if args.username or args.password:
        if not args.login_url:
            print("[!] --login-url is required when checking form auth.")
            return 1
        auth = {
            "method": "form",
            "login_url": args.login_url,
            "username_field": "username",
            "password_field": "password",
            "username": args.username,
            "password": args.password,
        }
        try:
            zap_scanner._setup_form_auth(auth, context_id, api_url, base_params, headers,
                                         user_name="strikehound-env-check-user")
            all_ok &= _report(True, "Form-based authentication configured + user created.")
        except Exception as e:
            all_ok &= _report(False, f"Form-auth setup failed: {e}")

    # 4. Cleanup
    try:
        requests.get(f"{api_url}/JSON/context/action/removeContext/",
                     params={**base_params, "contextName": args.context_name},
                     headers=headers, timeout=10)
    except requests.exceptions.RequestException:
        pass

    if all_ok:
        print("\n[+] ZAP environment check passed.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())