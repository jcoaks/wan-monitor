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

5. The ER605 only allows ONE active admin session at a time, and a new
   login silently invalidates whatever session was active before it — the
   API does not ask for confirmation (the "someone else is logged in"
   dialog in the web UI is purely client-side decoration; the raw API just
   kicks). So this script logs in, does its one API call, and immediately
   logs back out (``/admin/system?form=logout``, data={"method":"logout"})
   instead of holding the session open between polls — otherwise every
   time a human logged into the web UI, the next poll would silently log
   them right back out.
"""

import json
import logging
import os
import subprocess
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

# Human-friendly names for each WAN interface reported by the router.
# The router labels are "WAN1", "WAN/LAN2", "WAN/LAN3".
WAN_LABELS: dict[str, str] = {
    "WAN1":     "WAN1 NETUNO",
    "WAN/LAN2": "WAN2 CANTV",
    "WAN/LAN3": "WAN3 TECSOCA",
}
# how many consecutive failed HTTP polls (router unreachable / API broken)
# before we tell Telegram we can't even reach the router anymore
UNREACHABLE_ALERT_AFTER = int(os.environ.get("UNREACHABLE_ALERT_AFTER", "3"))

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]  # e.g. "@estadointernetcasa" or a numeric chat id
TELEGRAM_API_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

# How often we check Telegram for new /pausa /reanudar commands. Kept short
# and independent of POLL_INTERVAL_SECONDS so a /pausa takes effect almost
# immediately instead of waiting for the next router poll.
COMMAND_CHECK_INTERVAL_SECONDS = int(os.environ.get("COMMAND_CHECK_INTERVAL_SECONDS", "5"))
DEFAULT_PAUSE_MINUTES = int(os.environ.get("DEFAULT_PAUSE_MINUTES", "5"))
MAX_PAUSE_MINUTES = int(os.environ.get("MAX_PAUSE_MINUTES", "60"))

# Power-outage sentinel: a device with a DHCP-reserved IP that has no
# battery backup (e.g. the fridge), on the same network as this container's
# host. If the host running this container is on a UPS but the sentinel
# isn't, the sentinel going unreachable is a good proxy for "the power at
# home went out" (as opposed to just a WiFi/network hiccup, since the
# router itself is presumably also on the UPS). Optional: leave
# POWER_SENTINEL_IP unset to disable this check entirely.
POWER_SENTINEL_IP = os.environ.get("POWER_SENTINEL_IP", "").strip() or None
POWER_SENTINEL_LABEL = os.environ.get("POWER_SENTINEL_LABEL", "la nevera")
POWER_SENTINEL_MAC = os.environ.get("POWER_SENTINEL_MAC", "")  # informational only
PING_TIMEOUT_SECONDS = int(os.environ.get("PING_TIMEOUT_SECONDS", "2"))

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

    def logout(self) -> None:
        """
        Best-effort: release the single admin-session slot the ER605
        enforces, so a human can log into the web UI without this script's
        next poll silently kicking them back out. Never raises — if logout
        itself fails, the session was probably already gone anyway (e.g.
        someone else's login already replaced it).
        """
        if not self.stok:
            return
        path = f"/cgi-bin/luci/;stok={self.stok}/admin/system?form=logout"
        try:
            self._post_authenticated(path, {"method": "logout"})
        except (RouterAuthError, requests.RequestException) as exc:
            log.debug("Logout call failed (harmless): %s", exc)
        finally:
            self.stok = None

    def get_wan_status(self) -> list[dict]:
        """
        Logs in, fetches WAN status, and immediately logs back out again —
        every single call. See the module docstring (point 5) for why:
        holding the session open between polls means every time a human
        logs into the web UI, this script's very next poll would silently
        log them right back out, since the router only allows one active
        admin session and a fresh login just replaces whatever was there
        with no confirmation. Logging out right away keeps the window
        where this script "owns" the session down to a couple of requests
        every POLL_INTERVAL_SECONDS instead of indefinitely.

        Returns a list like:
          [{"state": "up", "t_label": "WAN1", "interface": "WAN1", ...}, ...]
        """
        self.login()
        try:
            path = f"/cgi-bin/luci/;stok={self.stok}/admin/online?form=online"
            body = self._post_authenticated(path, {"method": "get"})
            if body.get("error_code") != "0":
                raise RouterAuthError(f"WAN status call failed: {body}")
            return body["result"]
        finally:
            self.logout()


# --------------------------------------------------------------------------
# Power-outage sentinel (ping)
# --------------------------------------------------------------------------

def format_duration(seconds: float) -> str:
    """Compact human-readable duration, e.g. '2h 5m', '5m 30s', '12s'."""
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def ping_host(ip: str, timeout_seconds: int = PING_TIMEOUT_SECONDS) -> bool:
    """True if `ip` answers a single ICMP echo request within timeout_seconds."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_seconds), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds + 2,
        )
        return result.returncode == 0
    except Exception as exc:  # noqa: BLE001 - ping shelling out can fail in many ways
        log.warning("ping to %s raised an exception: %s", ip, exc)
        return False


# --------------------------------------------------------------------------
# Telegram
# --------------------------------------------------------------------------

def send_telegram_message(text: str) -> None:
    url = f"{TELEGRAM_API_BASE}/sendMessage"
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


def get_telegram_updates(offset: Optional[int]) -> list[dict]:
    """Long-poll-free fetch of new updates (timeout=0: return immediately)."""
    params = {"timeout": 0}
    if offset is not None:
        params["offset"] = offset
    try:
        resp = requests.get(f"{TELEGRAM_API_BASE}/getUpdates", params=params, timeout=10)
        resp.raise_for_status()
        body = resp.json()
        if not body.get("ok"):
            log.warning("getUpdates returned not-ok: %s", body)
            return []
        return body.get("result", [])
    except requests.RequestException as exc:
        log.warning("getUpdates failed: %s", exc)
        return []


def _chat_matches_target(chat: dict) -> bool:
    """Only accept commands from the configured channel/chat, not wherever else this bot may end up."""
    target = TELEGRAM_CHAT_ID.strip()
    chat_id = chat.get("id")
    username = chat.get("username")
    if target.lstrip("-").isdigit():
        return str(chat_id) == target
    if target.startswith("@") and username:
        return f"@{username}".lower() == target.lower()
    return False


def parse_command(text: str) -> Optional[tuple[str, Optional[int]]]:
    text = (text or "").strip()
    if not text.startswith("/"):
        return None
    parts = text[1:].split("@")[0].split()  # strip a "@botname" suffix Telegram sometimes appends
    if not parts:
        return None
    cmd = parts[0].lower()
    minutes = None
    if len(parts) > 1:
        try:
            minutes = int(parts[1])
        except ValueError:
            minutes = None
    return cmd, minutes


def process_telegram_commands(offset: Optional[int], paused_until: Optional[float]) -> tuple[Optional[int], Optional[float]]:
    """
    Checks for new /pausa /reanudar /estado commands sent to the channel and
    acts on them. Returns the (possibly updated) update-offset and
    paused_until timestamp for the caller to keep using.
    """
    updates = get_telegram_updates(offset)
    for update in updates:
        offset = update["update_id"] + 1
        post = update.get("channel_post") or update.get("message")
        if not post or "text" not in post or not _chat_matches_target(post.get("chat", {})):
            continue

        parsed = parse_command(post["text"])
        if not parsed:
            continue
        cmd, minutes = parsed

        if cmd in ("pausa", "pause"):
            minutes = minutes or DEFAULT_PAUSE_MINUTES
            minutes = max(1, min(minutes, MAX_PAUSE_MINUTES))
            paused_until = time.time() + minutes * 60
            send_telegram_message(
                f"⏸️ Monitoreo del router pausado {minutes} min — puedes entrar al panel "
                f"tranquilo. El sensor de luz sigue activo. Usa /reanudar para retomar antes."
            )
            log.info("Router polling paused for %s minutes via Telegram command", minutes)
        elif cmd in ("reanudar", "resume", "continuar"):
            if paused_until:
                paused_until = None
                send_telegram_message("▶️ Monitoreo del router reanudado.")
                log.info("Router polling resumed via Telegram command")
            else:
                send_telegram_message("El monitoreo ya estaba activo (no estaba pausado).")
        elif cmd in ("estado", "status"):
            if paused_until:
                remaining = max(0, int(paused_until - time.time()))
                send_telegram_message(f"⏸️ Pausado — quedan ~{remaining // 60}m {remaining % 60}s.")
            else:
                send_telegram_message("▶️ Monitoreo activo (no pausado).")

    return offset, paused_until


# --------------------------------------------------------------------------
# Main monitoring loop
# --------------------------------------------------------------------------

@dataclass
class InterfaceState:
    label: str
    state: str  # "up" / "down" / "unknown"


def friendly_label(iface: dict) -> str:
    raw = iface.get("t_label") or iface.get("interface", "?")
    return WAN_LABELS.get(raw, raw)


def format_status_line(iface: dict) -> str:
    label = friendly_label(iface)
    state = iface.get("state", "unknown")
    emoji = "✅" if state == "up" else "🔴"
    return f"{emoji} {label}: {state}"


def main() -> None:
    log.info(
        "Starting wan-monitor for %s (poll every %ss, commands checked every %ss)",
        BASE_URL,
        POLL_INTERVAL_SECONDS,
        COMMAND_CHECK_INTERVAL_SECONDS,
    )

    client = ER605Client(BASE_URL, ROUTER_USERNAME, ROUTER_PASSWORD)

    last_known: dict[str, str] = {}
    down_since: dict[str, float] = {}  # label -> loop_start when it went "down"
    consecutive_failures = 0
    unreachable_alert_sent = False
    first_failure_at: Optional[float] = None
    first_poll = True

    power_ok: Optional[bool] = None  # None = not checked yet
    power_down_since: Optional[float] = None
    power_first_poll = True
    if POWER_SENTINEL_IP:
        log.info(
            "Power-outage sentinel enabled: %s (%s)%s",
            POWER_SENTINEL_LABEL,
            POWER_SENTINEL_IP,
            f" mac={POWER_SENTINEL_MAC}" if POWER_SENTINEL_MAC else "",
        )

    # /pausa /reanudar /estado support. paused_until is a time.time()
    # deadline, or None when not paused. telegram_offset tracks which
    # updates we've already seen; primed once at startup so we don't act
    # on old messages sent before this container started.
    paused_until: Optional[float] = None
    backlog = get_telegram_updates(None)
    telegram_offset = (backlog[-1]["update_id"] + 1) if backlog else None
    send_telegram_message(
        "ℹ️ Comandos disponibles: /pausa [minutos] (default "
        f"{DEFAULT_PAUSE_MINUTES}, máx {MAX_PAUSE_MINUTES}), /reanudar, /estado — "
        "para pausar el chequeo del router mientras entras al panel web."
    )

    last_router_check = 0.0
    last_power_check = 0.0

    while True:
        loop_start = time.time()

        telegram_offset, paused_until = process_telegram_commands(telegram_offset, paused_until)

        if paused_until and loop_start >= paused_until:
            paused_until = None
            send_telegram_message("▶️ Se cumplió el tiempo de pausa — reanudando monitoreo del router.")

        router_check_due = (loop_start - last_router_check) >= POLL_INTERVAL_SECONDS

        if router_check_due and paused_until:
            log.debug("Router check due but paused until %s — skipping", paused_until)
            last_router_check = loop_start

        elif router_check_due:
            last_router_check = loop_start
            try:
                interfaces = client.get_wan_status()
                consecutive_failures = 0

                if unreachable_alert_sent:
                    if first_failure_at is not None:
                        send_telegram_message(
                            f"✅ El router vuelve a responder (estuvo sin contacto "
                            f"{format_duration(loop_start - first_failure_at)}). "
                            f"Reanudando monitoreo de WAN."
                        )
                    else:
                        send_telegram_message("✅ El router vuelve a responder. Reanudando monitoreo de WAN.")
                    unreachable_alert_sent = False
                first_failure_at = None

                changes = []
                for iface in interfaces:
                    label = friendly_label(iface)
                    state = iface.get("state", "unknown")
                    previous = last_known.get(label)

                    if previous is not None and previous != state:
                        changes.append((label, previous, state))
                        if state == "down":
                            down_since[label] = loop_start
                    last_known[label] = state

                if first_poll:
                    summary = "\n".join(format_status_line(i) for i in interfaces)
                    send_telegram_message(f"🟢 Monitor WAN iniciado.\n\nEstado actual:\n{summary}")
                    first_poll = False
                elif changes:
                    lines = []
                    for label, previous, state in changes:
                        if state == "up":
                            since = down_since.pop(label, None)
                            if since is not None:
                                lines.append(
                                    f"✅ {label} volvió a estar ONLINE "
                                    f"(estuvo caído {format_duration(loop_start - since)})"
                                )
                            else:
                                lines.append(f"✅ {label} volvió a estar ONLINE")
                        else:
                            lines.append(f"🔴 {label} se CAYÓ")
                    send_telegram_message("\n".join(lines))
                    for label, previous, state in changes:
                        log.info("%s: %s -> %s", label, previous, state)

            except RouterAuthError as exc:
                log.error("Auth/API error talking to router: %s", exc)
                consecutive_failures += 1
                if first_failure_at is None:
                    first_failure_at = loop_start
            except requests.RequestException as exc:
                log.error("Network error talking to router: %s", exc)
                consecutive_failures += 1
                if first_failure_at is None:
                    first_failure_at = loop_start

            if consecutive_failures == UNREACHABLE_ALERT_AFTER and not unreachable_alert_sent:
                send_telegram_message(
                    f"⚠️ No se puede contactar al router ({ROUTER_HOST}) desde hace "
                    f"{UNREACHABLE_ALERT_AFTER * POLL_INTERVAL_SECONDS}s. "
                    f"Puede ser el router, la red local, o el propio script."
                )
                unreachable_alert_sent = True

        # Power-outage sentinel: on its own schedule, independent of both the
        # WAN check above AND of /pausa — /pausa only pauses talking to the
        # router (that's what causes the session-kick problem), and losing
        # power-outage detection just because you're browsing the router UI
        # would defeat the point of having it.
        if POWER_SENTINEL_IP and (loop_start - last_power_check) >= POLL_INTERVAL_SECONDS:
            last_power_check = loop_start
            currently_ok = ping_host(POWER_SENTINEL_IP)

            if power_first_poll:
                status = "con luz ✅" if currently_ok else "SIN responder 🔴 (revisa si hay luz)"
                send_telegram_message(f"🔌 Sensor de luz ({POWER_SENTINEL_LABEL}) iniciado: {status}")
                power_first_poll = False
                if not currently_ok:
                    power_down_since = loop_start
            elif power_ok is not None and currently_ok != power_ok:
                if currently_ok:
                    if power_down_since is not None:
                        send_telegram_message(
                            f"💡 Volvió la luz ({POWER_SENTINEL_LABEL} responde de nuevo, "
                            f"estuvo sin luz {format_duration(loop_start - power_down_since)})"
                        )
                    else:
                        send_telegram_message(f"💡 Volvió la luz ({POWER_SENTINEL_LABEL} responde de nuevo)")
                    power_down_since = None
                else:
                    send_telegram_message(f"🔌 Se fue la luz ({POWER_SENTINEL_LABEL} dejó de responder)")
                    power_down_since = loop_start
                log.info("power sentinel: %s -> %s", power_ok, currently_ok)

            power_ok = currently_ok

        time.sleep(COMMAND_CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
