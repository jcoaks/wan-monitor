#!/usr/bin/env python3
"""
wan-monitor
-----------
Polls a TP-Link Omada ER605's local LuCI admin API for the real internal
status of each WAN interface, and sends a Telegram alert whenever one goes
down or comes back up.

This is a *separate* project from starr-server: its own bot, its own
Telegram channel, its own container.

Reverse-engineered from the ER605 v2.0 web UI (login.html / encrypt.js /
login.js). Key points:

1. Auth is done against ``/cgi-bin/luci/;stok=/login?form=login``.
   The password is never sent in the clear: the page first performs a
   "read" call against that same URL to fetch an RSA public key (n, e),
   then RSA-encrypts the password with a simple zero-padding scheme
   (NOT standard PKCS#1 v1.5) before POSTing it.

2. Every request to this endpoint (both the public-key "read" and the
   actual "login" write) is sent as ``application/x-www-form-urlencoded``
   with a single form field named ``data`` whose value is a JSON string:
     - read:  data={"method":"get"}
     - login: data={"method":"login","params":{"username":"...","password":"<hex>"}}

3. On success the login call returns ``{"result":{"stok":"..."}}`` and the
   response sets a ``sysauth`` cookie. All later API calls must include
   both the stok (embedded in the URL path) and the sysauth cookie.

4. WAN status lives at
   ``/cgi-bin/luci/;stok=<TOKEN>/admin/online?form=online`` (same
   data={"method":"get"} convention) and returns one entry per WAN
   interface: {"state": "up"/"down", "t_label": "WAN1", "interface": "WAN1", ...}
"""

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("wan-monitor")


# --------------------------------------------------------------------------
# Config (all from environment variables so this drops straight into
# docker-compose without touching code)
# --------------------------------------------------------------------------

ROUTER_SCHEME = os.environ.get("ROUTER_SCHEME", "https")  # "https" or "http"
ROUTER_HOST = os.environ.get("ROUTER_HOST", "192.168.0.1")
ROUTER_USERNAME = os.environ.get("ROUTER_USERNAME", "admin")
ROUTER_PASSWORD = os.environ["ROUTER_PASSWORD"]  # required, no default

POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "20"))
# how many consecutive failed HTTP polls (router unreachable / API broken)
# before we tell Telegram we can't even reach the router anymore
UNREACHABLE_ALERT_AFTER = int(os.environ.get("UNREACHABLE_ALERT_AFTER", "3"))

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]  # e.g. "@estadointernetcasa" or a numeric chat id

BASE_URL = f"{ROUTER_SCHEME}://{ROUTER_HOST}"
LOGIN_PATH = "/cgi-bin/luci/;stok=/login?form=login"
LOCALE_PATH = "/cgi-bin/luci/;stok=/locale?form=lang"

REQUEST_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    # The router's cgi-bin/luci endpoints do a Referer/Origin check as a CSRF
    # guard. Without these, it responds with a generic HTTP 404 instead of
    # ever reaching the application handler (confirmed by testing).
    "Referer": f"{BASE_URL}/webpages/login.html",
    "Origin": BASE_URL,
}


# --------------------------------------------------------------------------
# RSA encryption, replicating the router's own encrypt.js
# --------------------------------------------------------------------------

def rsa_encrypt_password(password: str, modulus_hex: str, exponent_hex: str) -> str:
    """
    Replicates $.su.encrypt(val, [n, e]) from encrypt.js:

      - the password is UTF-8 encoded
      - written at the *start* of a byte buffer the size of the RSA key
        (in bytes), zero-padded at the *end* (this is NOT PKCS#1 padding)
      - RSA-encrypted with the raw public operation c = m^e mod n
      - returned as a hex string, left-zero-padded to the full key length
    """
    n = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    key_len_bytes = (n.bit_length() + 7) // 8

    msg_bytes = password.encode("utf-8")
    if len(msg_bytes) > key_len_bytes:
        raise ValueError("password too long for RSA key size")
    padded = msg_bytes + b"\x00" * (key_len_bytes - len(msg_bytes))

    m = int.from_bytes(padded, byteorder="big")
    c = pow(m, e, n)

    hex_str = format(c, "x")
    # left-pad with zeros to the full key length (2 hex chars per byte)
    hex_str = hex_str.rjust(key_len_bytes * 2, "0")
    return hex_str


# --------------------------------------------------------------------------
# Router client
# --------------------------------------------------------------------------

class RouterAuthError(Exception):
    pass


class ER605Client:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.stok: Optional[str] = None

    def _post_login_endpoint(self, payload: dict) -> dict:
        """POST to the (unauthenticated) login URL with the data={json} convention."""
        resp = self.session.post(
            self.base_url + LOGIN_PATH,
            data={"data": json.dumps(payload)},
            headers=REQUEST_HEADERS,
            timeout=10,
            verify=False,
        )
        resp.raise_for_status()
        return resp.json()

    def _post_authenticated(self, path_with_stok: str, payload: dict) -> dict:
        resp = self.session.post(
            self.base_url + path_with_stok,
            data={"data": json.dumps(payload)},
            headers=REQUEST_HEADERS,
            timeout=10,
            verify=False,
        )
        resp.raise_for_status()
        return resp.json()

    def _fetch_public_key(self) -> tuple[str, str]:
        body = self._post_login_endpoint({"method": "get"})
        if body.get("error_code") != "0":
            raise RouterAuthError(f"failed to fetch RSA public key: {body}")
        modulus_hex, exponent_hex = body["result"]["password"]
        return modulus_hex, exponent_hex

    def _fetch_uptime(self) -> int:
        """
        The login page calls this ("u()" in login.js) right before encrypting
        the password every single time. It uses a *different* wire format
        than the login endpoint: plain ``operation=read`` form data, not the
        ``data={json}`` wrapper.
        """
        resp = self.session.post(
            self.base_url + LOCALE_PATH,
            data={"operation": "read"},
            headers=REQUEST_HEADERS,
            timeout=10,
            verify=False,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("error_code") != "0":
            raise RouterAuthError(f"failed to fetch router uptime: {body}")
        return int(body["result"]["uptime"])

    def login(self) -> None:
        modulus_hex, exponent_hex = self._fetch_public_key()
        uptime = self._fetch_uptime()

        # This is the piece that isn't visible anywhere in encrypt.js itself:
        # the password widget (chunk-common.js, password plugin's
        # "doEncrypt") appends "_<router uptime in seconds>" to the plaintext
        # before RSA-encrypting it, whenever withTimestamp=true (which it is
        # for the login form). Without this suffix the router accepts the
        # request but rejects the login with error_code 700, even though the
        # credentials and the RSA math are both correct.
        plaintext = f"{self.password}_{uptime}"
        encrypted_password = rsa_encrypt_password(plaintext, modulus_hex, exponent_hex)

        body = self._post_login_endpoint(
            {
                "method": "login",
                "params": {"username": self.username, "password": encrypted_password},
            }
        )
        if body.get("error_code") != "0":
            raise RouterAuthError(f"login failed: {body}")

        self.stok = body["result"]["stok"]
        log.info("Logged in to router, stok=%s...", self.stok[:8])

    def get_wan_status(self) -> list[dict]:
        """
        Returns a list like:
          [{"state": "up", "t_label": "WAN1", "interface": "WAN1", ...}, ...]
        Re-authenticates once and retries if the session looks expired.
        """
        if not self.stok:
            self.login()

        path = f"/cgi-bin/luci/;stok={self.stok}/admin/online?form=online"
        body = self._post_authenticated(path, {"method": "get"})

        if body.get("error_code") != "0":
            # session likely expired -> re-login once and retry
            log.warning("WAN status call failed (%s), re-authenticating", body.get("error_code"))
            self.stok = None
            self.login()
            path = f"/cgi-bin/luci/;stok={self.stok}/admin/online?form=online"
            body = self._post_authenticated(path, {"method": "get"})
            if body.get("error_code") != "0":
                raise RouterAuthError(f"WAN status call failed twice: {body}")

        return body["result"]


# --------------------------------------------------------------------------
# Telegram
# --------------------------------------------------------------------------

def send_telegram_message(text: str) -> None:
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        resp = requests.post(
            url,
            data={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=10,
        )
        if resp.status_code != 200:
            log.error("Telegram send failed: %s %s", resp.status_code, resp.text)
    except requests.RequestException as exc:
        log.error("Telegram send raised an exception: %s", exc)


# --------------------------------------------------------------------------
# Main monitoring loop
# --------------------------------------------------------------------------

@dataclass
class InterfaceState:
    label: str
    state: str  # "up" / "down" / "unknown"


def format_status_line(iface: dict) -> str:
    label = iface.get("t_label") or iface.get("interface", "?")
    state = iface.get("state", "unknown")
    emoji = "✅" if state == "up" else "🔴"
    return f"{emoji} {label}: {state}"


def main() -> None:
    log.info(
        "Starting wan-monitor for %s (poll every %ss)",
        BASE_URL,
        POLL_INTERVAL_SECONDS,
    )

    client = ER605Client(BASE_URL, ROUTER_USERNAME, ROUTER_PASSWORD)

    last_known: dict[str, str] = {}
    consecutive_failures = 0
    unreachable_alert_sent = False
    first_poll = True

    while True:
        try:
            interfaces = client.get_wan_status()
            consecutive_failures = 0

            if unreachable_alert_sent:
                send_telegram_message("✅ El router vuelve a responder. Reanudando monitoreo de WAN.")
                unreachable_alert_sent = False

            changes = []
            for iface in interfaces:
                label = iface.get("t_label") or iface.get("interface", "?")
                state = iface.get("state", "unknown")
                previous = last_known.get(label)

                if previous is not None and previous != state:
                    changes.append((label, previous, state))
                last_known[label] = state

            if first_poll:
                summary = "\n".join(format_status_line(i) for i in interfaces)
                send_telegram_message(f"🟢 wan-monitor iniciado. Estado actual:\n{summary}")
                first_poll = False
            elif changes:
                lines = []
                for label, previous, state in changes:
                    if state == "up":
                        lines.append(f"✅ {label} volvió a estar ONLINE (antes: {previous})")
                    else:
                        lines.append(f"🔴 {label} se CAYÓ (antes: {previous})")
                send_telegram_message("\n".join(lines))
                for label, previous, state in changes:
                    log.info("%s: %s -> %s", label, previous, state)

        except RouterAuthError as exc:
            log.error("Auth/API error talking to router: %s", exc)
            consecutive_failures += 1
        except requests.RequestException as exc:
            log.error("Network error talking to router: %s", exc)
            consecutive_failures += 1

        if consecutive_failures == UNREACHABLE_ALERT_AFTER and not unreachable_alert_sent:
            send_telegram_message(
                f"⚠️ No se puede contactar al router ({ROUTER_HOST}) desde hace "
                f"{UNREACHABLE_ALERT_AFTER * POLL_INTERVAL_SECONDS}s. "
                f"Puede ser el router, la red local, o el propio script."
            )
            unreachable_alert_sent = True

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
