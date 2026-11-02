#!/usr/bin/python3
# a plain defaults write is not a forced policy on macOS, so this builds a config profile the user approves once in System Settings
import ctypes
import json
import os
import struct
import subprocess
import sys
import time
import uuid

BUNDLES = [
    "com.google.Chrome",
    "com.google.Chrome.beta",
    "com.google.Chrome.dev",
    "com.google.Chrome.canary",
    "com.brave.Browser",
    "com.brave.Browser.origin",
    "com.brave.Browser.beta",
    "com.brave.Browser.nightly",
    "com.brave.Browser.dev",
    "com.microsoft.EdgeMac",
    "org.chromium.Chromium",
    "company.thebrowser.Browser",
    "com.vivaldi.Vivaldi",
]
KEY = "PasswordManagerEnabled"
APPDIR = os.path.expanduser("~/Library/Application Support/OpenPasswords")
PROFILE = os.path.join(APPDIR, "OpenPasswords-HidePasswordManager.mobileconfig")

# stdout is the native-messaging channel, so diagnostics go to a file. This log is what
# tells us whether a profile is actually forcing the key, per browser bundle.
LOG_DIR = os.path.expanduser("~/Library/Logs/OpenPasswords")
LOG_FILE = os.path.join(LOG_DIR, "policy.log")
LOG_MAX = 256 * 1024


def log(msg):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        try:
            if os.path.getsize(LOG_FILE) > LOG_MAX:
                os.replace(LOG_FILE, LOG_FILE + ".1")
        except OSError:
            pass
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} pid={os.getpid()} {msg}\n")
    except Exception:  # noqa: BLE001
        pass

_CF = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
_CF.CFStringCreateWithCString.restype = ctypes.c_void_p
_CF.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
_CF.CFPreferencesAppValueIsForced.restype = ctypes.c_bool
_CF.CFPreferencesAppValueIsForced.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


def _cfstr(x):
    return _CF.CFStringCreateWithCString(None, x.encode(), 0x08000100)


def forced_bundles():
    k = _cfstr(KEY)
    out = []
    for b in BUNDLES:
        try:
            if _CF.CFPreferencesAppValueIsForced(k, _cfstr(b)):
                out.append(b)
        except Exception as e:  # noqa: BLE001
            log(f"forced-check failed bundle={b} err={e!r}")
    return out


def is_forced():
    # true only when a managed profile actually forces the key
    return bool(forced_bundles())


def write_profile():
    import plistlib

    payloads = []
    for b in BUNDLES:
        payloads.append(
            {
                "PayloadType": b,
                "PayloadIdentifier": "com.openpasswords.hidepm." + b,
                "PayloadUUID": str(uuid.uuid4()).upper(),
                "PayloadEnabled": True,
                "PayloadVersion": 1,
                KEY: False,
            }
        )
    profile = {
        "PayloadType": "Configuration",
        "PayloadDisplayName": "Open Passwords - Hide Browser Password Manager",
        "PayloadDescription": "Disables the built-in password manager in Chromium browsers.",
        "PayloadIdentifier": "com.openpasswords.hidepm",
        "PayloadUUID": "1D8B2E90-0000-4000-A000-4F70656E5057",
        "PayloadVersion": 1,
        "PayloadRemovalDisallowed": False,
        "PayloadContent": payloads,
    }
    os.makedirs(APPDIR, exist_ok=True)
    with open(PROFILE, "wb") as f:
        plistlib.dump(profile, f)
    log(f"profile written path={PROFILE} bytes={os.path.getsize(PROFILE)} bundles={len(BUNDLES)}")


def send(obj):
    b = json.dumps(obj).encode()
    sys.stdout.buffer.write(struct.pack("<I", len(b)) + b)
    sys.stdout.buffer.flush()


def main():
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        sys.exit(0)
    (n,) = struct.unpack("<I", raw)
    action = json.loads(sys.stdin.buffer.read(n)).get("action")

    forced = forced_bundles()
    log(f"request action={action!r} forced={forced}")

    if action == "set":
        write_profile()
        r = subprocess.run(["open", PROFILE], capture_output=True, text=True)
        log(f"open profile rc={r.returncode} err={(r.stderr or '').strip()[:200]!r}")
        now = is_forced()
        send({"ok": True, "hidden": now, "needsApproval": not now, "forcedBundles": forced_bundles()})
    elif action == "clear":
        # profiles can only be removed by the user in System Settings
        r = subprocess.run(["open", "x-apple.systempreferences:com.apple.preferences.configurationprofiles"])
        log(f"open profiles pane rc={r.returncode}")
        send({"ok": True, "hidden": is_forced(), "forcedBundles": forced_bundles()})
    elif action == "get":
        send({"ok": True, "hidden": bool(forced), "forcedBundles": forced})
    else:
        log(f"unknown action={action!r}")
        send({"ok": False, "error": "unknown action"})


if __name__ == "__main__":
    log("started")
    main()
