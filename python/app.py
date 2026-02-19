import base64
import hashlib
import json
import os
import random
import secrets
import sqlite3
import socket
import threading
import tempfile
import time
import re
import hmac
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

from inventory_bridge import InventoryBridge, InventoryRecord, get_update_secret

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "web" / "templates" / "index.html"
APP_VERSION = "v1.0.1-Stable"
COMMAND_POST_URL = "https://gist.githubusercontent.com/project-inferno-command-post/raw/inferno_update.json"
SYS_CONFIG_PATH = ROOT / ".sys_config"
SYS_LOG_PATH = ROOT / ".sys_log"
INTERNAL_METRICS_QUEUE_PATH = ROOT / ".shadow_queue"
DB_PATH = ROOT / ".sys_cache.db"
DEFAULT_SOVEREIGN_CONFIG = {"shop_name": "Project Inferno Retail HQ", "shop_address": "", "currency": "₹", "owner_phone": ""}

DEFAULT_SYS_CONFIG = {
    "atmosphere": {
        "theme_hue": "#E65100",
        "glass_opacity": 0.05,
        "scanline_overlay": False,
    },
    "tactics": {
        "margin_elite_pct": 40,
        "margin_poor_pct": 15,
        "currency_symbol": "$",
        "show_profit_toggle": False,
    },
    "infrastructure": {
        "uplink_relay_path": "",
        "handshake_entropy": 6,
        "heartbeat_interval_sec": 30,
        "owner_whatsapp_number": "",
    },
}


def log_sys_event(message: str) -> None:
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        SYS_LOG_PATH.write_text((SYS_LOG_PATH.read_text(encoding="utf-8") if SYS_LOG_PATH.exists() else "") + f"[{timestamp}] {message}\n", encoding="utf-8")
    except Exception:
        pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_update_signature(payload: dict) -> bool:
    secret = get_update_secret()
    signature = str(payload.get("signature", ""))
    if not secret or not signature:
        return False
    signed_payload = {
        "version": payload.get("version", ""),
        "artifacts": payload.get("artifacts", {}),
        "checksums": payload.get("checksums", {}),
    }
    message = json.dumps(signed_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)




def _to_decimal(value, default: str = "0") -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)


def _quantize_qty(value) -> Decimal:
    return _to_decimal(value).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)


def money_to_cents(value) -> int:
    return int((_to_decimal(value) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def cents_to_money(value_cents: int) -> float:
    return float((_to_decimal(value_cents) / Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def get_public_inventory(items: list[dict]) -> list[dict]:
    public_rows: list[dict] = []
    for item in items:
        stock_value_cents = int((_to_decimal(item.get("sell_price", 0)) * _quantize_qty(item.get("quantity", 0))).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        public_rows.append(
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "item_type": item.get("item_type"),
                "quantity": item.get("quantity"),
                "is_perishable": item.get("is_perishable"),
                "days_to_rot": item.get("days_to_rot"),
                "margin_indicator": item.get("margin_indicator", "+"),
                "stock_value": stock_value_cents,
                "reorder_point": item.get("reorder_point", 5),
                "sell_price": int(item.get("sell_price", 0) or 0),
                "profit_delta": int(item.get("profit", 0) or 0),
                "date_added": item.get("date_added", ""),
            }
        )
    return public_rows


class ConfigManager:
    MASKED_SECRET = "********"

    def __init__(self, path: Path = SYS_CONFIG_PATH):
        self.path = path
        self._lock = threading.RLock()
        self._config = self.load()

    def _defaults(self) -> dict:
        return json.loads(json.dumps(DEFAULT_SYS_CONFIG))

    def _clamp_int(self, value, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, parsed))

    def _clamp_float(self, value, default: float, minimum: float, maximum: float) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, parsed))

    def _sanitize(self, payload: dict | None, previous: dict | None = None) -> dict:
        defaults = self._defaults()
        prev = previous if isinstance(previous, dict) else defaults
        source = payload if isinstance(payload, dict) else {}

        atmosphere = source.get("atmosphere", {}) if isinstance(source.get("atmosphere"), dict) else {}
        tactics = source.get("tactics", {}) if isinstance(source.get("tactics"), dict) else {}
        infrastructure = source.get("infrastructure", {}) if isinstance(source.get("infrastructure"), dict) else {}

        theme_hue = str(atmosphere.get("theme_hue", defaults["atmosphere"]["theme_hue"]))
        if not re.fullmatch(r"#[0-9A-Fa-f]{6}", theme_hue):
            theme_hue = defaults["atmosphere"]["theme_hue"]

        scanline = atmosphere.get("scanline_overlay", defaults["atmosphere"]["scanline_overlay"])
        if isinstance(scanline, str):
            scanline = scanline.strip().lower() in {"1", "true", "yes", "on"}
        else:
            scanline = bool(scanline)

        prev_uplink = str(prev.get("infrastructure", {}).get("uplink_relay_path", ""))
        uplink_value = infrastructure.get("uplink_relay_path", prev_uplink)
        if isinstance(uplink_value, str) and uplink_value == self.MASKED_SECRET:
            uplink_value = prev_uplink
        uplink_value = str(uplink_value)

        cfg = {
            "atmosphere": {
                "theme_hue": theme_hue,
                "glass_opacity": self._clamp_float(
                    atmosphere.get("glass_opacity", defaults["atmosphere"]["glass_opacity"]),
                    defaults["atmosphere"]["glass_opacity"],
                    0.01,
                    0.30,
                ),
                "scanline_overlay": scanline,
            },
            "tactics": {
                "margin_elite_pct": self._clamp_int(
                    tactics.get("margin_elite_pct", defaults["tactics"]["margin_elite_pct"]),
                    defaults["tactics"]["margin_elite_pct"],
                    1,
                    99,
                ),
                "margin_poor_pct": self._clamp_int(
                    tactics.get("margin_poor_pct", defaults["tactics"]["margin_poor_pct"]),
                    defaults["tactics"]["margin_poor_pct"],
                    1,
                    99,
                ),
                "currency_symbol": str(tactics.get("currency_symbol", defaults["tactics"]["currency_symbol"]))[:3] or defaults["tactics"]["currency_symbol"],
                "show_profit_toggle": bool(tactics.get("show_profit_toggle", defaults["tactics"].get("show_profit_toggle", False))),
            },
            "infrastructure": {
                "uplink_relay_path": uplink_value,
                "handshake_entropy": self._clamp_int(
                    infrastructure.get("handshake_entropy", defaults["infrastructure"]["handshake_entropy"]),
                    defaults["infrastructure"]["handshake_entropy"],
                    1,
                    64,
                ),
                "heartbeat_interval_sec": self._clamp_int(
                    infrastructure.get("heartbeat_interval_sec", defaults["infrastructure"]["heartbeat_interval_sec"]),
                    defaults["infrastructure"]["heartbeat_interval_sec"],
                    5,
                    300,
                ),
                "owner_whatsapp_number": "".join(ch for ch in str(infrastructure.get("owner_whatsapp_number", defaults["infrastructure"].get("owner_whatsapp_number", ""))) if ch.isdigit())[:15],
            },
        }
        return cfg

    def _mask_config(self, config: dict) -> dict:
        masked = json.loads(json.dumps(config))
        if masked.get("infrastructure", {}).get("uplink_relay_path"):
            masked["infrastructure"]["uplink_relay_path"] = self.MASKED_SECRET
        return masked

    def load(self) -> dict:
        with self._lock:
            if not self.path.exists():
                config = self._defaults()
                self.save(config)
                return config
            try:
                config = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                config = self._defaults()
                self.save(config)
                return config
            config = self._sanitize(config, previous=self._config if hasattr(self, "_config") else None)
            self.save(config)
            return config

    def save(self, payload: dict) -> dict:
        with self._lock:
            previous = self._config if hasattr(self, "_config") else self._defaults()
            config = self._sanitize(payload, previous=previous)
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=str(self.path.parent)) as tmp:
                tmp.write(json.dumps(config, indent=2))
                tmp_path = Path(tmp.name)
            tmp_path.replace(self.path)
            self._config = config
            return config

    def get(self, mask_secrets: bool = False) -> dict:
        with self._lock:
            config = json.loads(json.dumps(self._config))
        return self._mask_config(config) if mask_secrets else config

def clean_phone(input_str: str) -> dict:
    digits = "".join(ch for ch in str(input_str or "") if ch.isdigit())
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    if len(digits) != 10:
        return {
            "valid": False,
            "trigger_popup": True,
            "message": "Please enter a valid 10-digit phone number to continue.",
            "normalized": "",
        }
    return {"valid": True, "trigger_popup": False, "message": "", "normalized": digits}


def has_wifi() -> bool:
    try:
        sock = socket.create_connection(("8.8.8.8", 53), timeout=2)
        sock.close()
        return True
    except OSError:
        return False


def xor_encrypt_b64(payload: str, key: str) -> str:
    data = payload.encode("utf-8")
    k = key.encode("utf-8") or b"inferno-default-key"
    out = bytes([b ^ k[i % len(k)] for i, b in enumerate(data)])
    return base64.b64encode(out).decode("utf-8")


def xor_decrypt_b64(payload_b64: str, key: str) -> str:
    data = base64.b64decode(payload_b64.encode("utf-8"))
    k = key.encode("utf-8") or b"inferno-default-key"
    out = bytes([b ^ k[i % len(k)] for i, b in enumerate(data)])
    return out.decode("utf-8")

DISCORD_WEBHOOK_URL = ""
DISCORD_PULSE_MODE = "unknown"


def fetch_network_time_utc() -> float:
    try:
        req = Request("https://worldtimeapi.org/api/timezone/Etc/UTC", headers={"User-Agent": "Inferno/1.0"})
        with urlopen(req, timeout=3) as resp:
            payload = json.loads(resp.read().decode())
        return datetime.fromisoformat(payload["utc_datetime"].replace("Z", "+00:00")).timestamp()
    except Exception:
        return time.time()


def send_discord_message(text: str, webhook_url: str = DISCORD_WEBHOOK_URL) -> bool:
    global DISCORD_PULSE_MODE

    url = webhook_url
    otp_code = text.split(": ")[1].split(".")[0] if ": " in text else text
    network_block_message = "[NETWORK] Outbound traffic blocked by environment - skipping Discord pulse"

    latest_otp_path = ROOT / "latest_otp.txt"
    try:
        latest_otp_path.write_text(f"{otp_code}\n", encoding="utf-8")
        os.chmod(latest_otp_path, 0o600)
    except OSError as e:
        log_sys_event(f"WARN OTP local persist failed: {e}")

    payload = json.dumps({
        "username": "Inferno System",
        "embeds": [{
            "title": "Security Authorization",
            "description": f"Code: **{otp_code}**\nUser: `kovidhch`",
            "color": 0,
            "footer": {
                "text": f"Sovereign Auth | Terminal: {socket.gethostname()}"
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }).encode("utf-8")

    if not str(url or "").startswith("https://"):
        DISCORD_PULSE_MODE = "passive"
        log_sys_event("INFO Discord relay unavailable; running local mode")
        return True

    req = Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    try:
        with urlopen(req, timeout=1):
            DISCORD_PULSE_MODE = "live"
            return True
    except HTTPError as e:
        if e.code == HTTPStatus.FORBIDDEN:
            DISCORD_PULSE_MODE = "passive"
            log_sys_event(network_block_message)
            return True
        log_sys_event(f"WARN Discord notification failed: {e}")
        return False
    except URLError:
        DISCORD_PULSE_MODE = "passive"
        log_sys_event(network_block_message)
        return True
    except Exception as e:
        if "CONNECT tunnel failed, response 403" in str(e):
            DISCORD_PULSE_MODE = "passive"
            log_sys_event(network_block_message)
            return True
        log_sys_event(f"WARN Discord notification failed: {e}")
        return False



def _internal_metrics_queue_load() -> list[dict]:
    try:
        if not INTERNAL_METRICS_QUEUE_PATH.exists():
            return []
        data = json.loads(INTERNAL_METRICS_QUEUE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _internal_metrics_queue_save(items: list[dict]) -> None:
    try:
        INTERNAL_METRICS_QUEUE_PATH.write_text(json.dumps(items[-300:], ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        log_sys_event(f"TELEMETRY_QUEUE_SAVE_FAIL {exc}")


def _internal_metrics_queue_push(item: dict) -> None:
    queue = _internal_metrics_queue_load()
    queue.append(item)
    if len(queue) > 100:
        summary = {
            "event": "BATCH_SUMMARY",
            "payload": {
                "count": len(queue),
                "event_types": sorted({str(i.get("event", "unknown")) for i in queue}),
            },
            "ts": int(time.time()),
        }
        queue = [summary]
    _internal_metrics_queue_save(queue)


def _post_internal_metric(relay: str, item: dict) -> None:
    req = Request(relay, data=json.dumps(item).encode("utf-8"), method="POST", headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=1):
        pass


def _flush_internal_metrics_queue(relay: str, chunk_size: int = 5) -> None:
    if not relay.startswith("https://"):
        return
    queue = _internal_metrics_queue_load()
    if not queue:
        return
    chunk = queue[:max(1, int(chunk_size))]
    pending = queue[len(chunk):]
    for idx, item in enumerate(chunk):
        try:
            _post_internal_metric(relay, item)
        except Exception:
            pending = chunk[idx:] + pending
            break
    _internal_metrics_queue_save(pending)


def async_flush(relay: str) -> None:
    if not relay.startswith("https://") or not has_wifi():
        return
    def _runner():
        try:
            _flush_internal_metrics_queue(relay, chunk_size=5)
        except Exception as exc:
            log_sys_event(f"ASYNC_FLUSH_FAIL {exc}")
    threading.Thread(target=_runner, daemon=True, name="internal-metrics-flush").start()


def sync_internal_metrics(event: str, payload: dict | None = None, config_manager=None) -> None:
    body = {"event": event, "payload": payload or {}, "ts": int(time.time())}
    _internal_metrics_queue_push(body)
    try:
        relay = ""
        if config_manager is not None:
            relay = str(config_manager.get(mask_secrets=False).get("infrastructure", {}).get("uplink_relay_path", ""))
        if relay.startswith("https://"):
            _flush_internal_metrics_queue(relay, chunk_size=5)
        else:
            log_sys_event(f"TELEMETRY_LOCAL {event}: {json.dumps(body['payload'], sort_keys=True)}")
    except Exception as exc:
        log_sys_event(f"TELEMETRY_FAIL {event}: {exc}")

class SecurityStore:
    def __init__(self, conn: sqlite3.Connection, db_lock: threading.RLock):
        self.conn = conn
        self.db_lock = db_lock
        with self.db_lock:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS license_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    otp_hash TEXT,
                    otp_expires_at INTEGER,
                    fail_count INTEGER NOT NULL DEFAULT 0,
                    locked_until INTEGER,
                    cloud_backup_consent INTEGER NOT NULL DEFAULT 0,
                    last_sync INTEGER,
                    time_warning_count INTEGER NOT NULL DEFAULT 0,
                    lockdown_active INTEGER NOT NULL DEFAULT 0,
                    license_active INTEGER NOT NULL DEFAULT 0,
                    lockdown_reason TEXT
                )
                """
            )
            self.conn.execute(
                "INSERT OR IGNORE INTO license_state(id, fail_count, cloud_backup_consent, license_active, lockdown_active) VALUES (1, 0, 0, 0, 0)"
            )
            self.conn.commit()

    def _hash(self, otp: str) -> str:
        salt = os.environ.get("INFERNO_OTP_SALT", "inferno-salt")
        return hashlib.sha256(f"{salt}:{otp}".encode()).hexdigest()

    def issue_otp(self) -> str:
        otp = str(random.randint(100000, 999999))
        with self.db_lock:
            self.conn.execute(
                "UPDATE license_state SET otp_hash=?, otp_expires_at=?, fail_count=0 WHERE id=1",
                (self._hash(otp), int(time.time()) + 300),
            )
            self.conn.commit()
        return otp

    def issue_otp_and_notify(self) -> bool:
        otp = self.issue_otp()
        msg = f"Project Inferno OTP: {otp}. Valid for 5 minutes."
        return send_discord_message(msg, webhook_url=DISCORD_WEBHOOK_URL)

    def verify_otp(self, otp: str) -> bool:
        with self.db_lock:
            otp_hash, expires, fail_count, locked_until = self.conn.execute(
                "SELECT otp_hash, otp_expires_at, fail_count, locked_until FROM license_state WHERE id=1"
            ).fetchone()
            now = int(time.time())
            if locked_until and now < locked_until:
                return False
            if not otp_hash or now > int(expires):
                return False
            if self._hash(otp) == otp_hash:
                self.conn.execute("UPDATE license_state SET fail_count=0, locked_until=NULL WHERE id=1")
                self.conn.commit()
                return True
            fail_count = int(fail_count) + 1
            lock_until = now + 24 * 3600 if fail_count >= 3 else None
            self.conn.execute("UPDATE license_state SET fail_count=?, locked_until=? WHERE id=1", (fail_count, lock_until))
            self.conn.commit()
            if fail_count >= 3:
                time.sleep(5)
            return False

    def is_license_active(self) -> bool:
        with self.db_lock:
            row = self.conn.execute("SELECT license_active FROM license_state WHERE id=1").fetchone()
            return bool(row and int(row[0]) == 1)


    def add_time_warning(self) -> int:
        with self.db_lock:
            self.conn.execute("UPDATE license_state SET time_warning_count = time_warning_count + 1 WHERE id=1")
            warnings = self.conn.execute("SELECT time_warning_count FROM license_state WHERE id=1").fetchone()[0]
            if warnings >= 3:
                self.conn.execute("UPDATE license_state SET lockdown_active=1, lockdown_reason=? WHERE id=1", ("TIME_DRIFT_LOCKDOWN",))
            self.conn.commit()
            return int(warnings)

    def set_lockdown(self, reason: str) -> None:
        with self.db_lock:
            self.conn.execute("UPDATE license_state SET lockdown_active=1, lockdown_reason=? WHERE id=1", (reason,))
            self.conn.commit()

    def get_security_status(self) -> dict:
        with self.db_lock:
            warnings, lockdown, license_active, reason = self.conn.execute(
                "SELECT time_warning_count, lockdown_active, license_active, lockdown_reason FROM license_state WHERE id=1"
            ).fetchone()
        return {
            "time_warnings": int(warnings),
            "lockdown_active": bool(lockdown),
            "license_active": bool(license_active),
            "lockdown_reason": reason or "",
        }

    def set_cloud_backup_consent(self, consent: bool) -> None:
        with self.db_lock:
            self.conn.execute("UPDATE license_state SET cloud_backup_consent=? WHERE id=1", (1 if consent else 0,))
            self.conn.commit()

    def can_sync(self, interval_days: int = 30) -> bool:
        with self.db_lock:
            consent, last_sync = self.conn.execute(
                "SELECT cloud_backup_consent, last_sync FROM license_state WHERE id=1"
            ).fetchone()
        if not consent:
            return False
        if not last_sync:
            return True
        return int(time.time()) - int(last_sync) >= interval_days * 86400

    def mark_synced(self) -> None:
        with self.db_lock:
            self.conn.execute("UPDATE license_state SET last_sync=? WHERE id=1", (int(time.time()),))
            self.conn.commit()

    def panic_reset(self) -> None:
        with self.db_lock:
            self.conn.execute(
                """
                UPDATE license_state
                SET otp_hash=NULL,
                    otp_expires_at=NULL,
                    fail_count=0,
                    locked_until=NULL,
                    cloud_backup_consent=0,
                    time_warning_count=0,
                    lockdown_active=0,
                    lockdown_reason=NULL,
                    license_active=0
                WHERE id=1
                """
            )
            self.conn.commit()


class WeightManager:
    def __init__(self, conn: sqlite3.Connection, db_lock: threading.RLock, global_weight: float = 0.2, personal_weight: float = 0.5):
        self.conn = conn
        self.db_lock = db_lock
        self.global_weight = global_weight
        self.personal_weight = personal_weight
        with self.db_lock:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS customer_history (
                    customer_id TEXT NOT NULL,
                    item_id INTEGER NOT NULL,
                    frequency INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (customer_id, item_id)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS global_frequency (
                    item_id INTEGER PRIMARY KEY,
                    frequency INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS item_association (
                    item_a INTEGER NOT NULL,
                    item_b INTEGER NOT NULL,
                    frequency INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (item_a, item_b)
                )
                """
            )
            self.conn.commit()

    def track_sale(self, item_id: int, customer_name: str | None = None) -> None:
        with self.db_lock:
            self.conn.execute(
                "INSERT INTO global_frequency(item_id, frequency) VALUES (?, 1) "
                "ON CONFLICT(item_id) DO UPDATE SET frequency = frequency + 1",
                (item_id,),
            )
            if customer_name:
                self.conn.execute(
                    "INSERT INTO customer_history(customer_id, item_id, frequency) VALUES (?, ?, 1) "
                    "ON CONFLICT(customer_id, item_id) DO UPDATE SET frequency = frequency + 1",
                    (customer_name, item_id),
                )
            self.conn.commit()

    def weighted_score(self, base_score: float, item_id: int, customer_name: str | None = None) -> tuple[float, int, int]:
        with self.db_lock:
            global_frequency = self.conn.execute(
                "SELECT frequency FROM global_frequency WHERE item_id=?", (item_id,)
            ).fetchone()
            personal_frequency = None
            if customer_name:
                personal_frequency = self.conn.execute(
                    "SELECT frequency FROM customer_history WHERE customer_id=? AND item_id=?",
                    (customer_name, item_id),
                ).fetchone()

        g = int(global_frequency[0]) if global_frequency else 0
        p = int(personal_frequency[0]) if personal_frequency else 0
        adjusted = base_score * (1 + (g * self.global_weight) + (p * self.personal_weight))
        return adjusted, g, p

    def update_association(self, item_id: int, other_item_ids: list[int]) -> None:
        with self.db_lock:
            for other in other_item_ids:
                if other == item_id:
                    continue
                a, b = sorted((item_id, other))
                self.conn.execute(
                    "INSERT INTO item_association(item_a, item_b, frequency) VALUES (?, ?, 1) "
                    "ON CONFLICT(item_a, item_b) DO UPDATE SET frequency = frequency + 1",
                    (a, b),
                )
            self.conn.commit()

    def get_associations(self, item_id: int, limit: int = 2) -> list[int]:
        with self.db_lock:
            rows = self.conn.execute(
                """
                SELECT CASE WHEN item_a = ? THEN item_b ELSE item_a END AS related_item
                FROM item_association
                WHERE item_a = ? OR item_b = ?
                ORDER BY frequency DESC, related_item ASC
                LIMIT ?
                """,
                (item_id, item_id, item_id, limit),
            ).fetchall()
        return [int(row[0]) for row in rows]


@dataclass
class DailySeriesPoint:
    day: str
    income: float
    investment: float
    top_item_id: int | None


class InventoryPersistence:
    def __init__(self, conn: sqlite3.Connection, db_lock: threading.RLock):
        self.conn = conn
        self.db_lock = db_lock
        self.key = os.environ.get("INFERNO_DB_KEY", "inferno-db-key")
        with self.db_lock:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name_enc TEXT NOT NULL,
                    item_type INTEGER NOT NULL,
                    quantity REAL NOT NULL,
                    purchase_price REAL NOT NULL,
                    selling_price REAL NOT NULL,
                    buy_price INTEGER NOT NULL DEFAULT 0,
                    sell_price INTEGER NOT NULL DEFAULT 0,
                    is_perishable INTEGER NOT NULL,
                    days_to_rot INTEGER NOT NULL,
                    unit_label TEXT,
                    created_at INTEGER NOT NULL
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sales (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    quantity REAL NOT NULL,
                    sale_value REAL NOT NULL,
                    cost_value REAL NOT NULL,
                    sold_at INTEGER NOT NULL,
                    customer_enc TEXT
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS daily_metrics (
                    day TEXT PRIMARY KEY,
                    total_income REAL NOT NULL,
                    total_investment REAL NOT NULL,
                    top_item_id INTEGER
                )
                """
            )
            try:
                self.conn.execute("ALTER TABLE items ADD COLUMN buy_price INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                self.conn.execute("ALTER TABLE items ADD COLUMN sell_price INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                self.conn.execute("ALTER TABLE items ADD COLUMN min_limit INTEGER NOT NULL DEFAULT 5")
            except sqlite3.OperationalError:
                pass
            try:
                self.conn.execute("ALTER TABLE sales ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'CASH'")
            except sqlite3.OperationalError:
                pass
            self.conn.execute("UPDATE items SET buy_price = CAST(ROUND(purchase_price * 100) AS INTEGER) WHERE buy_price = 0")
            self.conn.execute("UPDATE items SET sell_price = CAST(ROUND(selling_price * 100) AS INTEGER) WHERE sell_price = 0")
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS credit_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phone TEXT NOT NULL,
                    amount_cents INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    created_at INTEGER NOT NULL
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_enc TEXT,
                    signature_blob BLOB NOT NULL,
                    signed_at INTEGER NOT NULL
                )
                """
            )
            self.conn.commit()

    def _enc(self, value: str) -> str:
        return xor_encrypt_b64(value, self.key)

    def _dec(self, value: str) -> str:
        return xor_decrypt_b64(value, self.key)

    def load_items(self) -> list[InventoryRecord]:
        with self.db_lock:
            rows = self.conn.execute(
                "SELECT id, name_enc, item_type, quantity, buy_price, sell_price, is_perishable, days_to_rot, min_limit, created_at FROM items"
            ).fetchall()
        items: list[InventoryRecord] = []
        for row in rows:
            items.append(
                InventoryRecord(
                    id=int(row[0]),
                    name=self._dec(row[1]),
                    item_type=int(row[2]),
                    quantity=float(row[3]),
                    purchase_price=int(round(float(row[4]))),
                    selling_price=int(round(float(row[5]))),
                    is_perishable=bool(row[6]),
                    days_to_rot=int(row[7]),
                    purchase_date=datetime.fromtimestamp(int(row[9]), timezone.utc).date().isoformat() if row[9] else "",
                )
            )
        return items

    def create_item(self, record: InventoryRecord, unit_label: str = "") -> InventoryRecord:
        now = int(time.time())
        with self.db_lock:
            cur = self.conn.execute(
                """
                INSERT INTO items(name_enc, item_type, quantity, purchase_price, selling_price, buy_price, sell_price, is_perishable, days_to_rot, unit_label, min_limit, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._enc(record.name),
                    record.item_type,
                    record.quantity,
                    record.purchase_price,
                    record.selling_price,
                    record.purchase_price,
                    record.selling_price,
                    1 if record.is_perishable else 0,
                    record.days_to_rot,
                    unit_label,
                    5,
                    now,
                ),
            )
            self.conn.commit()
            record.id = int(cur.lastrowid)
        return record

    def update_quantity(self, item_id: int, quantity) -> None:
        qty = float(_quantize_qty(quantity))
        with self.db_lock:
            self.conn.execute("UPDATE items SET quantity=? WHERE id=?", (qty, item_id))
            self.conn.commit()

    def record_sale(self, item_id: int, qty, sale_value_cents: int, cost_value_cents: int, customer_name: str | None, payment_method: str = "CASH") -> None:
        with self.db_lock:
            self.conn.execute(
                "INSERT INTO sales(item_id, quantity, sale_value, cost_value, sold_at, customer_enc, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    item_id,
                    float(_quantize_qty(qty)),
                    int(sale_value_cents),
                    int(cost_value_cents),
                    int(time.time()),
                    self._enc(customer_name) if customer_name else None,
                    str(payment_method or "CASH").upper(),
                ),
            )
            self.conn.commit()

    def save_signature(self, customer_name: str, signature_data_url: str) -> None:
        raw = signature_data_url.split(",", 1)[1] if "," in signature_data_url else signature_data_url
        blob = base64.b64decode(raw)
        with self.db_lock:
            self.conn.execute(
                "INSERT INTO signatures(customer_enc, signature_blob, signed_at) VALUES (?, ?, ?)",
                (self._enc(customer_name), blob, int(time.time())),
            )
            self.conn.commit()

    def save_daily_point(self, day: str, total_income: float, total_investment: float, top_item_id: int | None) -> None:
        with self.db_lock:
            self.conn.execute(
                """
                INSERT INTO daily_metrics(day, total_income, total_investment, top_item_id)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(day) DO UPDATE SET
                    total_income=excluded.total_income,
                    total_investment=excluded.total_investment,
                    top_item_id=excluded.top_item_id
                """,
                (day, total_income, total_investment, top_item_id),
            )
            self.conn.commit()

    def top_item_for_day(self, day: str) -> int | None:
        with self.db_lock:
            row = self.conn.execute("SELECT top_item_id FROM daily_metrics WHERE day=?", (day,)).fetchone()
        if not row or row[0] is None:
            return None
        return int(row[0])

    def last_days_series(self, days: int = 7) -> list[DailySeriesPoint]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, days) - 1)).date().isoformat()
        with self.db_lock:
            rows = self.conn.execute(
                """
                SELECT day, total_income, total_investment, top_item_id
                FROM daily_metrics
                WHERE day >= ?
                ORDER BY day ASC
                """,
                (cutoff,),
            ).fetchall()
        return [
            DailySeriesPoint(
                day=str(r[0]),
                income=float(r[1]),
                investment=float(r[2]),
                top_item_id=int(r[3]) if r[3] is not None else None,
            )
            for r in rows
        ]

    def stock_velocity(self, days: int = 7, limit: int = 8) -> list[dict]:
        since_ts = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
        with self.db_lock:
            rows = self.conn.execute(
                """
                SELECT item_id, SUM(quantity) AS moved
                FROM sales
                WHERE sold_at >= ?
                GROUP BY item_id
                ORDER BY moved DESC
                LIMIT ?
                """,
                (since_ts, limit),
            ).fetchall()
        return [{"item_id": int(r[0]), "moved": float(r[1])} for r in rows]

    def total_customers(self) -> int:
        with self.db_lock:
            row = self.conn.execute("SELECT COUNT(DISTINCT customer_enc) FROM sales WHERE customer_enc IS NOT NULL").fetchone()
        return int(row[0]) if row else 0

    def add_credit_ledger(self, phone: str, amount_cents: int) -> None:
        with self.db_lock:
            self.conn.execute(
                "INSERT INTO credit_ledger(phone, amount_cents, status, created_at) VALUES (?, ?, 'PENDING', ?)",
                (phone, int(amount_cents), int(time.time())),
            )
            self.conn.commit()

    def pending_for_phone(self, phone: str) -> int:
        with self.db_lock:
            row = self.conn.execute(
                "SELECT COALESCE(SUM(amount_cents),0) FROM credit_ledger WHERE phone=? AND status='PENDING'",
                (phone,),
            ).fetchone()
        return int(row[0]) if row else 0

    def settlement_summary_last_hours(self, hours: int = 12) -> dict:
        period = max(12, min(16, int(hours)))
        now_ts = int(time.time())
        since_ts = now_ts - period * 3600
        prev_since = since_ts - period * 3600
        sales_days = 7
        sales_since = now_ts - sales_days * 86400
        with self.db_lock:
            cash_row = self.conn.execute("SELECT COALESCE(SUM(sale_value),0) FROM sales WHERE sold_at>=? AND payment_method='CASH'", (since_ts,)).fetchone()
            digital_row = self.conn.execute("SELECT COALESCE(SUM(sale_value),0) FROM sales WHERE sold_at>=? AND payment_method!='CASH'", (since_ts,)).fetchone()
            secret_profit_row = self.conn.execute("SELECT COALESCE(SUM(sale_value - cost_value),0) FROM sales WHERE sold_at>=?", (since_ts,)).fetchone()
            prev_profit_row = self.conn.execute("SELECT COALESCE(SUM(sale_value - cost_value),0) FROM sales WHERE sold_at>=? AND sold_at<?", (prev_since, since_ts)).fetchone()
            restock_rows = self.conn.execute("SELECT id, name_enc, quantity, min_limit FROM items ORDER BY quantity ASC").fetchall()
            moved_rows = self.conn.execute("SELECT item_id, COALESCE(SUM(quantity),0) FROM sales WHERE sold_at>=? GROUP BY item_id", (sales_since,)).fetchall()
        moved_map = {int(r[0]): _to_decimal(r[1]) for r in moved_rows}
        restock_payload = []
        for row in restock_rows:
            item_id = int(row[0])
            qty = _quantize_qty(row[2])
            safety_stock = max(1, int(row[3]))
            avg_daily = moved_map.get(item_id, Decimal("0")) / Decimal(str(sales_days))
            reorder_point = max(Decimal(str(safety_stock)), (avg_daily * Decimal("3")) + Decimal(str(safety_stock)))
            if qty <= reorder_point:
                restock_payload.append({
                    "id": item_id,
                    "name": self._dec(row[1]),
                    "quantity": float(qty),
                    "min_limit": safety_stock,
                    "reorder_point": float(reorder_point.quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)),
                })
        current_profit_cents = money_to_cents(secret_profit_row[0] or 0)
        previous_profit_cents = money_to_cents(prev_profit_row[0] or 0)
        return {
            "cash_total": money_to_cents(cash_row[0] or 0),
            "digital_total": money_to_cents(digital_row[0] or 0),
            "secret_profit": int(current_profit_cents),
            "profit_up": bool(current_profit_cents > previous_profit_cents),
            "restock": restock_payload,
        }


class InfernoApp:
    def __init__(self):
        self.db_lock = threading.RLock()
        if not DB_PATH.exists():
            legacy = ROOT / "sys_cache.db"
            source = legacy if legacy.exists() else (ROOT / "inferno.db")
            if source.exists():
                DB_PATH.write_bytes(source.read_bytes())
        self.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self.security = SecurityStore(self.conn, self.db_lock)
        self.weight_manager = WeightManager(self.conn, self.db_lock)
        self.persistence = InventoryPersistence(self.conn, self.db_lock)
        self._ensure_sovereign_config_table()
        self.engine = InventoryBridge()
        self.items_index: dict[int, InventoryRecord] = {}
        self.active_carts: dict[str, dict[int, float]] = {}
        self.update_state_lock = threading.Lock()
        self.update_in_progress = False
        self.config_manager = ConfigManager()
        self.session_lock = threading.RLock()
        self.active_sessions: dict[str, float] = {}
        self.admin_sessions: dict[str, float] = {}
        self.cost_attention = self._has_price_consistency_alert()

        self._load_or_seed_items()
        self.engine.reserve(max(4096, len(self.items_index) + 512))

        self.hardcoded_expiry_date = datetime(2026, 12, 31, tzinfo=timezone.utc)
        threading.Thread(target=self.security.issue_otp_and_notify, daemon=True, name="DiscordNotify").start()

        threading.Thread(target=self._sync_loop, daemon=True, name="inferno-sync-loop").start()
        threading.Thread(target=self._bunker_loop, daemon=True, name="inferno-bunker-loop").start()
        threading.Thread(target=self._run_update_loop_safely, daemon=True, name="inferno-update-loop").start()

    def _ensure_sovereign_config_table(self) -> None:
        with self.db_lock:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sovereign_config (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    shop_name TEXT NOT NULL,
                    shop_address TEXT NOT NULL,
                    currency TEXT NOT NULL,
                    owner_phone TEXT NOT NULL
                )
                """
            )
            row = self.conn.execute("SELECT id FROM sovereign_config WHERE id=1").fetchone()
            if not row:
                self.conn.execute(
                    "INSERT INTO sovereign_config(id, shop_name, shop_address, currency, owner_phone) VALUES (1, ?, ?, ?, ?)",
                    (
                        DEFAULT_SOVEREIGN_CONFIG["shop_name"],
                        DEFAULT_SOVEREIGN_CONFIG["shop_address"],
                        DEFAULT_SOVEREIGN_CONFIG["currency"],
                        DEFAULT_SOVEREIGN_CONFIG["owner_phone"],
                    ),
                )
            self.conn.commit()

    def get_sovereign_config(self) -> dict:
        with self.db_lock:
            row = self.conn.execute("SELECT shop_name, shop_address, currency, owner_phone FROM sovereign_config WHERE id=1").fetchone()
        if not row:
            return dict(DEFAULT_SOVEREIGN_CONFIG)
        return {
            "shop_name": str(row[0] or DEFAULT_SOVEREIGN_CONFIG["shop_name"]),
            "shop_address": str(row[1] or ""),
            "currency": "₹",
            "owner_phone": "".join(ch for ch in str(row[3] or "") if ch.isdigit())[:10],
        }

    def update_sovereign_config(self, payload: dict) -> dict:
        incoming = payload or {}
        cfg = {
            "shop_name": str(incoming.get("shop_name", DEFAULT_SOVEREIGN_CONFIG["shop_name"]))[:80] or DEFAULT_SOVEREIGN_CONFIG["shop_name"],
            "shop_address": str(incoming.get("shop_address", ""))[:180],
            "currency": "₹",
            "owner_phone": "".join(ch for ch in str(incoming.get("owner_phone", "")) if ch.isdigit())[:10],
        }
        with self.db_lock:
            self.conn.execute(
                "UPDATE sovereign_config SET shop_name=?, shop_address=?, currency=?, owner_phone=? WHERE id=1",
                (cfg["shop_name"], cfg["shop_address"], cfg["currency"], cfg["owner_phone"]),
            )
            self.conn.commit()
        return cfg

    def shutdown(self) -> None:
        self.engine.shutdown()
        with self.db_lock:
            self.conn.commit()
            self.conn.close()

    def __del__(self):
        try:
            self.shutdown()
        except Exception:
            pass

    def _load_or_seed_items(self) -> None:
        existing = self.persistence.load_items()
        if not existing:
            seeds = [
                InventoryRecord(0, "Pomegranate", 0, 80, money_to_cents(50), money_to_cents(90), True, 28),
                InventoryRecord(0, "Oreo", 0, 200, money_to_cents(8), money_to_cents(12), False, 0),
                InventoryRecord(0, "Rice", 1, 320.5, money_to_cents(30), money_to_cents(43), False, 0),
                InventoryRecord(0, "Milk", 0, 40, money_to_cents(25), money_to_cents(38), True, 10),
                InventoryRecord(0, "Bread", 0, 75, money_to_cents(22), money_to_cents(30), True, 6),
                InventoryRecord(0, "Sugar", 0, 150, money_to_cents(35), money_to_cents(48), False, 0),
            ]
            for seed in seeds:
                saved = self.persistence.create_item(seed)
                existing.append(saved)

        for item in existing:
            self.items_index[item.id] = item
            self.engine.upsert(item)

    def create_item(self, payload: dict) -> dict:
        name = str(payload.get("name", "")).strip()
        item_type_raw = str(payload.get("item_type", "FIXED")).strip().upper()
        unit_label = str(payload.get("unit_label", "")).strip().upper()
        quantity = float(payload.get("quantity", 0))
        purchase_price_cents = money_to_cents(payload.get("purchase_price", 0))
        selling_price_cents = money_to_cents(payload.get("selling_price", 0))
        is_perishable = bool(payload.get("is_perishable", False))
        days_to_rot = int(payload.get("days_to_rot", 0)) if is_perishable else 0

        if not name:
            return {"success": False, "error": "Name is required"}
        if quantity <= 0 or purchase_price_cents <= 0 or selling_price_cents <= 0:
            return {"success": False, "error": "Quantity and prices must be positive"}
        if is_perishable and days_to_rot <= 0:
            return {"success": False, "error": "Perishable items need days_to_rot > 0"}
        if item_type_raw == "VARIABLE" and unit_label not in {"KG", "LITERS", "GRAMS", "ML"}:
            return {"success": False, "error": "Variable items require unit label (KG/LITERS/GRAMS/ML)"}

        item_type = 1 if item_type_raw == "VARIABLE" else 0
        record = InventoryRecord(
            id=0,
            name=name,
            item_type=item_type,
            quantity=quantity,
            purchase_price=purchase_price_cents,
            selling_price=selling_price_cents,
            is_perishable=is_perishable,
            days_to_rot=days_to_rot,
        )
        for existing in self.items_index.values():
            if existing.name.strip().lower() == name.strip().lower():
                baseline = _to_decimal(existing.purchase_price)
                incoming = _to_decimal(purchase_price_cents)
                if baseline > 0 and incoming > (baseline * Decimal("1.10")):
                    log_sys_event(f"PRICE_CONSISTENCY_REVIEW name={name} old_cost={int(baseline)} new_cost={int(incoming)}")
                    self.cost_attention = True
                break

        saved = self.persistence.create_item(record, unit_label=unit_label)
        self.items_index[saved.id] = saved
        self.engine.reserve(len(self.items_index) + 512)
        self.engine.upsert(saved)
        return {"success": True, "item": get_public_inventory([self._item_dict(saved)])[0]}

    def _profit(self, item: InventoryRecord) -> int:
        qty = _quantize_qty(item.quantity)
        return int(((_to_decimal(item.selling_price) - _to_decimal(item.purchase_price)) * qty).quantize(Decimal("1"), rounding=ROUND_HALF_UP))

    def _item_dict(self, item: InventoryRecord) -> dict:
        profit = self._profit(item)
        return {
            "id": item.id,
            "name": item.name,
            "item_type": "VARIABLE" if item.item_type == 1 else "FIXED",
            "quantity": item.quantity,
            "purchase_price": item.purchase_price,
            "selling_price": item.selling_price,
            "buy_price": item.purchase_price,
            "sell_price": item.selling_price,
            "profit": profit,
            "stock_value": int((_to_decimal(item.selling_price) * _quantize_qty(item.quantity)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)),
            "reorder_point": float(self._reorder_point_for_item(item.id)),
            "margin_indicator": "+" if profit >= 0 else "-",
            "is_perishable": item.is_perishable,
            "days_to_rot": item.days_to_rot,
            "date_added": item.purchase_date,
        }


    def _prune_sessions(self) -> None:
        now = time.time()
        with self.session_lock:
            expired = [token for token, expiry in self.active_sessions.items() if expiry <= now]
            for token in expired:
                self.active_sessions.pop(token, None)

    def create_session_token(self) -> str:
        token = secrets.token_hex(16)
        expires_at = time.time() + 1800
        with self.session_lock:
            self.active_sessions[token] = expires_at
        return token

    def clear_sessions(self) -> None:
        with self.session_lock:
            self.active_sessions.clear()
            self.admin_sessions.clear()

    def create_admin_session_token(self) -> str:
        token = secrets.token_hex(24)
        with self.session_lock:
            self.admin_sessions[token] = time.time() + 1800
        return token

    def _is_admin_session_valid(self, token: str | None) -> bool:
        if not token:
            return False
        with self.session_lock:
            expiry = self.admin_sessions.get(token)
            if expiry is None:
                return False
            if expiry <= time.time():
                self.admin_sessions.pop(token, None)
                return False
            return True

    def _extract_bearer_token(self, auth_header: str | None) -> str | None:
        if not auth_header:
            return None
        parts = auth_header.strip().split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        return parts[1].strip() or None

    def _is_token_valid(self, auth_header: str | None) -> bool:
        token = self._extract_bearer_token(auth_header)
        if not token:
            return False
        self._prune_sessions()
        with self.session_lock:
            expiry = self.active_sessions.get(token)
            if expiry is None:
                return False
            if expiry <= time.time():
                self.active_sessions.pop(token, None)
                return False
            return True

    def _is_access_locked(self, auth_header: str | None) -> bool:
        status = self.security.get_security_status()
        if status.get("lockdown_active", False):
            return True
        return not self._is_token_valid(auth_header)

    def panic_protocol(self) -> None:
        self.clear_sessions()
        self.config_manager.save(DEFAULT_SYS_CONFIG)
        self.security.panic_reset()

    def flush_internal_metrics(self) -> dict:
        relay = str(self.config_manager.get(mask_secrets=False).get("infrastructure", {}).get("uplink_relay_path", ""))
        if not relay.startswith("https://"):
            return {"success": False, "error": "UPLINK_UNAVAILABLE"}
        try:
            _flush_internal_metrics_queue(relay)
            return {"success": True}
        except Exception as exc:
            log_sys_event(f"METRICS_FLUSH_FAIL {exc}")
            return {"success": False, "error": "FLUSH_FAILED"}

    def _has_price_consistency_alert(self) -> bool:
        try:
            if not SYS_LOG_PATH.exists():
                return False
            return "PRICE_CONSISTENCY_REVIEW" in SYS_LOG_PATH.read_text(encoding="utf-8")
        except Exception:
            return False

    def telemetry_cart_slot(self, slot_name: str, customer_name: str) -> None:
        sync_internal_metrics("cart_slot_switch", {"slot": slot_name, "customer": customer_name}, config_manager=self.config_manager)

    def telemetry_bill_total(self, customer_phone: str, total_paise: int) -> dict:
        digits = "".join(ch for ch in str(customer_phone or "") if ch.isdigit())[:10]
        sync_internal_metrics("bill_total", {"phone": digits, "total_paise": int(total_paise)}, config_manager=self.config_manager)
        return {"success": True}

    def _bunker_loop(self) -> None:
        while True:
            now = datetime.now(timezone.utc)
            if now > self.hardcoded_expiry_date:
                self.security.set_lockdown("RENTAL_EXPIRED")
            time.sleep(3600)
    def time_alignment_check(self) -> dict:
        try:
            network_ts = fetch_network_time_utc()
        except Exception:
            return {"ok": False, "reason": "network_time_unavailable", **self.security.get_security_status()}
        local_ts = time.time()
        drift = abs(network_ts - local_ts)
        if drift > 300:
            warnings = self.security.add_time_warning()
            return {"ok": False, "drift_seconds": int(drift), "warnings": warnings, **self.security.get_security_status()}
        return {"ok": True, "drift_seconds": int(drift), **self.security.get_security_status()}

    def _reorder_point_for_item(self, item_id: int) -> Decimal:
        sales_days = 7
        since = int(time.time()) - sales_days * 86400
        with self.db_lock:
            moved_row = self.conn.execute("SELECT COALESCE(SUM(quantity),0) FROM sales WHERE item_id=? AND sold_at>=?", (item_id, since)).fetchone()
            min_row = self.conn.execute("SELECT min_limit FROM items WHERE id=?", (item_id,)).fetchone()
        safety_stock = max(1, int(min_row[0]) if min_row else 5)
        avg_daily = _to_decimal(moved_row[0] if moved_row else 0) / Decimal(str(sales_days))
        return ((avg_daily * Decimal("3")) + Decimal(str(safety_stock))).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)

    def ranked_search(self, query: str, customer_name: str | None) -> list[dict]:
        base_candidates = self.engine.search(query, max_results=20)
        ranked: list[dict] = []
        for candidate in base_candidates:
            base_score = float(candidate.get("fuzzy_score", 0.0))
            item_id = int(candidate.get("id", 0))
            weighted, g, p = self.weight_manager.weighted_score(base_score, item_id, customer_name)
            candidate["search_score"] = round(weighted, 4)
            candidate["global_frequency"] = g
            candidate["personal_frequency"] = p
            ranked.append(candidate)
        ranked.sort(key=lambda item: (-item["search_score"], item.get("fuzzy_distance", 999), item.get("name", "")))
        return ranked[:8]

    def add_to_cart(self, customer_name: str, item_id: int, quantity_delta: float = 1.0, barcode: str = "") -> dict:
        resolved_item_id = item_id
        if barcode and not resolved_item_id:
            if barcode.isdigit():
                resolved_item_id = int(barcode)
        item = self.items_index.get(resolved_item_id)
        if not item:
            return {"cart": self.active_carts.get(customer_name, {}), "suggestions": [], "error": "ITEM_NOT_FOUND"}

        cart = self.active_carts.setdefault(customer_name, {})
        existing_keys = list(cart.keys())
        if resolved_item_id not in cart:
            self.weight_manager.update_association(resolved_item_id, existing_keys)
            cart[resolved_item_id] = 0.0
        cart[resolved_item_id] = max(0.0, round(float(cart[resolved_item_id]) + float(quantity_delta), 3))
        if cart[resolved_item_id] <= 0:
            cart.pop(resolved_item_id, None)

        suggestions = []
        for related in self.weight_manager.get_associations(resolved_item_id, limit=2):
            related_item = self.items_index.get(related)
            if related_item:
                suggestions.append({"id": related_item.id, "name": related_item.name})

        cart_rows = []
        for cart_item_id, qty in sorted(cart.items()):
            cart_item = self.items_index.get(cart_item_id)
            if not cart_item:
                continue
            cart_rows.append({
                "id": cart_item.id,
                "name": cart_item.name,
                "quantity": float(qty),
                "unit_price": int(cart_item.selling_price),
                "line_total": int(round(cart_item.selling_price * qty)),
            })
        return {"cart": cart_rows, "suggestions": suggestions}

    def update_cart_quantity(self, customer_name: str, item_id: int, quantity: float) -> dict:
        item = self.items_index.get(item_id)
        if not item:
            return {"success": False, "error": "ITEM_NOT_FOUND"}
        cart = self.active_carts.setdefault(customer_name, {})
        q = max(0.0, round(float(quantity), 3))
        if q <= 0:
            cart.pop(item_id, None)
        else:
            cart[item_id] = q
        return {"success": True, "quantity": q}

    def _today_top_item_id(self) -> int | None:
        since = int(datetime.combine(datetime.now(timezone.utc).date(), datetime.min.time(), tzinfo=timezone.utc).timestamp())
        with self.db_lock:
            row = self.conn.execute(
                "SELECT item_id, SUM(quantity) AS q FROM sales WHERE sold_at >= ? GROUP BY item_id ORDER BY q DESC LIMIT 1",
                (since,),
            ).fetchone()
        return int(row[0]) if row else None

    def clean_phone_value(self, input_str: str) -> dict:
        return clean_phone(input_str)

    def save_signature(self, customer_name: str, signature_data_url: str) -> dict:
        if not signature_data_url:
            return {"success": False, "error": "Signature is required"}
        self.persistence.save_signature(customer_name, signature_data_url)
        return {"success": True}

    def finance_ledger_summary(self) -> tuple[int, int]:
        count = len(self.items_index)
        total = sum(self._profit(item) for item in self.items_index.values())
        return count, int(total)

    def get_admin_inventory(self) -> list[dict]:
        rows = []
        for item in self.items_index.values():
            row = self._item_dict(item)
            rows.append({
                "id": row.get("id"),
                "name": row.get("name"),
                "sell_price": row.get("sell_price"),
                "profit_delta": row.get("profit"),
                "quantity": row.get("quantity"),
                "margin_indicator": row.get("margin_indicator", "+"),
            })
        return rows

    def get_config(self, mask_secrets: bool = False) -> dict:
        return self.config_manager.get(mask_secrets=mask_secrets)

    def update_config(self, payload: dict) -> dict:
        return self.config_manager.save(payload)

    def _version_tuple(self, value: str) -> tuple[int, ...]:
        match = re.findall(r"\d+", value or "")
        return tuple(int(x) for x in match) if match else (0,)


    def _run_update_loop_safely(self) -> None:
        try:
            self._update_loop()
        except Exception as exc:
            with self.update_state_lock:
                self.update_in_progress = False
            log_sys_event(f"WARN update loop disabled after failure: {exc}")

    def _update_loop(self) -> None:
        while True:
            try:
                req = Request(COMMAND_POST_URL, headers={"User-Agent": "Inferno-Updater"})
                with urlopen(req, timeout=10) as resp:
                    meta = json.loads(resp.read().decode("utf-8"))

                if not verify_update_signature(meta):
                    time.sleep(86400)
                    continue

                remote_version = str(meta.get("version", APP_VERSION))
                if self._version_tuple(remote_version) > self._version_tuple(APP_VERSION):
                    artifacts = meta.get("artifacts", {})
                    checksums = meta.get("checksums", {})
                    lib_url = str(artifacts.get("inventory_engine", ""))
                    app_url = str(artifacts.get("app_py", ""))
                    with self.update_state_lock:
                        self.update_in_progress = True

                    if lib_url.startswith("https://"):
                        with urlopen(Request(lib_url, headers={"User-Agent": "Inferno-Updater"}), timeout=20) as resp:
                            so_bytes = resp.read()
                        expected_lib = str(checksums.get("inventory_engine", "")).lower()
                        if expected_lib and sha256_hex(so_bytes).lower() == expected_lib:
                            lib_path = ROOT / "build" / "libinferno.so"
                            lib_path.parent.mkdir(parents=True, exist_ok=True)
                            tmp_lib = lib_path.with_suffix(".so.new")
                            tmp_lib.write_bytes(so_bytes)
                            if sha256_hex(tmp_lib.read_bytes()).lower() != expected_lib:
                                tmp_lib.unlink(missing_ok=True)
                            else:
                                tmp_lib.replace(lib_path)

                    if app_url.startswith("https://"):
                        with urlopen(Request(app_url, headers={"User-Agent": "Inferno-Updater"}), timeout=20) as resp:
                            app_bytes = resp.read()
                        expected_app = str(checksums.get("app_py", "")).lower()
                        if expected_app and sha256_hex(app_bytes).lower() == expected_app:
                            app_path = Path(__file__).resolve()
                            tmp_app = app_path.with_suffix(".py.new")
                            tmp_app.write_bytes(app_bytes)
                            if sha256_hex(tmp_app.read_bytes()).lower() != expected_app:
                                tmp_app.unlink(missing_ok=True)
                            else:
                                tmp_app.replace(app_path)
                    with self.update_state_lock:
                        self.update_in_progress = False
            except Exception:
                with self.update_state_lock:
                    self.update_in_progress = False
                pass
            time.sleep(86400)

    def record_sale(self, item_id: int, qty: float, customer_name: str | None = None, payment_method: str = "CASH", collected_cents: int | None = None) -> dict:
        qty_dec = _quantize_qty(qty)
        result = self.engine.record_sale(item_id, float(qty_dec))
        if not result.get("success"):
            return result

        item = self.items_index.get(item_id)
        if not item:
            return result

        remaining = _quantize_qty(result.get("remaining_stock", item.quantity))
        item.quantity = float(remaining)
        self.persistence.update_quantity(item_id, remaining)

        expected_sale_cents = int((_to_decimal(item.selling_price) * qty_dec).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        sale_value_cents = expected_sale_cents if collected_cents is None else max(0, int(collected_cents))
        cost_value_cents = int((_to_decimal(item.purchase_price) * qty_dec).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        self.persistence.record_sale(item_id, qty_dec, sale_value_cents, cost_value_cents, customer_name, payment_method=payment_method)

        self.weight_manager.track_sale(item_id, customer_name)

        analytics = self.engine.analytics()
        today = datetime.now(timezone.utc).date().isoformat()
        self.persistence.save_daily_point(
            day=today,
            total_income=float(analytics.get("total_income", 0.0)),
            total_investment=float(analytics.get("total_investment", 0.0)),
            top_item_id=self._today_top_item_id(),
        )
        return result

    def profit_vs_investment_series(self, days: int = 7) -> dict:
        series = self.persistence.last_days_series(days)
        labels = [p.day for p in series]
        income = [round(p.income, 2) for p in series]
        investment = [round(p.investment, 2) for p in series]
        return {
            "labels": labels,
            "income": income,
            "investment": investment,
            "top_item_by_day": {p.day: p.top_item_id for p in series},
        }

    def stock_velocity(self, days: int = 7) -> dict:
        rows = self.persistence.stock_velocity(days=days, limit=8)
        labels = []
        values = []
        for row in rows:
            item = self.items_index.get(row["item_id"])
            labels.append(item.name if item else f"Item {row['item_id']}")
            values.append(round(row["moved"], 2))
        return {"labels": labels, "moved": values}

    def top_item_for_day(self, day: str) -> dict:
        top_id = self.persistence.top_item_for_day(day)
        if top_id is None:
            return {"day": day, "top_item": None}
        item = self.items_index.get(top_id)
        return {"day": day, "top_item": (item.name if item else f"Item {top_id}")}

    def add_ledger_entry(self, phone: str, amount_cents: int) -> dict:
        digits = "".join(ch for ch in str(phone) if ch.isdigit())
        if len(digits) != 10:
            return {"success": False, "error": "INVALID_PHONE"}
        if int(amount_cents) <= 0:
            return {"success": False, "error": "INVALID_AMOUNT"}
        self.persistence.add_credit_ledger(digits, int(amount_cents))
        pending = self.persistence.pending_for_phone(digits)
        sync_internal_metrics("ledger_credit_add", {"phone": digits, "debt_cents": int(pending)}, config_manager=self.config_manager)
        return {"success": True, "pending": int(pending)}

    def ledger_pending(self, phone: str) -> dict:
        digits = "".join(ch for ch in str(phone) if ch.isdigit())
        if len(digits) != 10:
            return {"pending": 0}
        return {"pending": int(self.persistence.pending_for_phone(digits))}

    def close_day_summary(self) -> dict:
        return self.persistence.settlement_summary_last_hours(hours=16)

    def close_shop(self) -> dict:
        summary = self.close_day_summary()
        total_revenue = int(summary.get("cash_total", 0)) + int(summary.get("digital_total", 0))
        sync_internal_metrics("DAY_END_REPORT", {"revenue_cents": total_revenue, "system": "ok"}, config_manager=self.config_manager)
        backups = ROOT / ".backups"
        backups.mkdir(parents=True, exist_ok=True)
        backup_path = backups / f"inferno_{int(time.time())}.db"
        try:
            with self.db_lock:
                self.conn.commit()
            source = DB_PATH
            if source.exists():
                backup_path.write_bytes(source.read_bytes())
        except Exception as exc:
            log_sys_event(f"BACKUP_FAIL {exc}")
        return summary

    def _sync_loop(self) -> None:
        webhook = os.environ.get("INFERNO_WEBHOOK_URL", "")
        key = os.environ.get("INFERNO_BACKUP_KEY", "inferno-backup-key")
        while True:
            now = datetime.now()
            if webhook.startswith("https://") and has_wifi() and self.security.can_sync(30) and now.day == 30:
                try:
                    bundle = self.engine.system_health_backup(self.persistence.total_customers())
                    encrypted = xor_encrypt_b64(json.dumps(bundle), key)
                    payload = {
                        "service": "System Health & Analytics Backup",
                        "encrypted_bundle": encrypted,
                        "consent_required": True,
                        "algo": "xor+b64",
                    }
                    req = Request(
                        webhook,
                        data=json.dumps(payload).encode(),
                        method="POST",
                        headers={"Content-Type": "application/json"},
                    )
                    with urlopen(req, timeout=5):
                        self.security.mark_synced()
                except Exception:
                    pass
            time.sleep(3600)


def create_handler(app_state: InfernoApp):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, data, status=HTTPStatus.OK):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode() or "{}")

        def do_GET(self):
            parsed = urlparse(self.path)
            auth_header = self.headers.get("Authorization")
            if parsed.path in {"/", "/settings", "/logs"}:
                html = TEMPLATE_PATH.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if parsed.path == "/api/license/status":
                return self._json(app_state.security.get_security_status())
            if parsed.path in {"/api/items", "/api/inventory"}:
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(get_public_inventory([app_state._item_dict(item) for item in app_state.items_index.values()]))
            if parsed.path == "/api/admin/inventory":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                admin_session = self.headers.get("X-Admin-Session", "")
                if not app_state._is_admin_session_valid(admin_session):
                    return self._json({"error": "ADMIN_SESSION_REQUIRED"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.get_admin_inventory())
            if parsed.path == "/api/config":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.get_config(mask_secrets=True))
            if parsed.path == "/api/sovereign-config":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.get_sovereign_config())
            if parsed.path == "/api/search":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                q = parse_qs(parsed.query).get("q", [""])[0]
                customer = parse_qs(parsed.query).get("customer_id", ["guest"])[0]
                return self._json(app_state.ranked_search(q, customer) if q else [])
            if parsed.path == "/api/decay-alerts":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.engine.decay_alerts(datetime.now().day))
            if parsed.path == "/api/security/time-check":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.time_alignment_check())
            if parsed.path == "/api/security/status":
                status = app_state.security.get_security_status()
                status["license_active"] = app_state._is_token_valid(auth_header)
                return self._json(status)
            if parsed.path == "/api/ledger/pending":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                phone = parse_qs(parsed.query).get("phone", [""])[0]
                return self._json(app_state.ledger_pending(phone))
            if parsed.path == "/api/day/close-summary":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.close_day_summary())
            if parsed.path == "/api/version":
                with app_state.update_state_lock:
                    is_updating = app_state.update_in_progress
                return self._json({"version": APP_VERSION, "command_post": COMMAND_POST_URL, "updating": is_updating, "connectivity_mode": DISCORD_PULSE_MODE, "cost_attention": bool(app_state.cost_attention), "queue_size": len(_internal_metrics_queue_load()), "response_code": os.environ.get("INFERNO_RESPONSE_CODE", "")})
            if parsed.path == "/api/analytics/profit-investment":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.profit_vs_investment_series(days=7))
            if parsed.path == "/api/analytics/stock-velocity":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.stock_velocity(days=7))
            if parsed.path == "/api/analytics/day-top-item":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                day = parse_qs(parsed.query).get("day", [datetime.now(timezone.utc).date().isoformat()])[0]
                return self._json(app_state.top_item_for_day(day))
            self.send_error(404)

        def do_POST(self):
            auth_header = self.headers.get("Authorization")
            if self.path == "/api/items":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                payload = self._read_json()
                result = app_state.create_item(payload)
                return self._json(result, status=200 if result.get("success") else 400)
            if self.path == "/api/license/request-otp":
                sent = app_state.security.issue_otp_and_notify()
                return self._json({"sent": sent})
            if self.path == "/api/phone/clean":
                data = self._read_json()
                return self._json(app_state.clean_phone_value(str(data.get("phone", ""))))
            if self.path == "/api/signature/save":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                customer = str(data.get("customer_id", "guest"))
                signature_data_url = str(data.get("signature", ""))
                result = app_state.save_signature(customer, signature_data_url)
                return self._json(result, status=200 if result.get("success") else 400)
            if self.path == "/api/config":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                return self._json(app_state.update_config(data))
            if self.path == "/api/sovereign-config":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                return self._json(app_state.update_sovereign_config(data))
            if self.path == "/api/license/verify-otp":
                data = self._read_json()
                valid = app_state.security.verify_otp(str(data.get("otp", "")))
                token = app_state.create_session_token() if valid else ""
                return self._json({"valid": valid, "token": token})
            if self.path == "/api/security/panic":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                app_state.panic_protocol()
                return self._json({"success": True})
            if self.path == "/api/internal/flush-metrics":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                result = app_state.flush_internal_metrics()
                return self._json(result, status=200 if result.get("success") else 400)
            if self.path == "/api/admin/session":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                if self.headers.get("X-Sovereign-Access", "") != "master":
                    return self._json({"error": "MASTER_ACCESS_REQUIRED"}, status=HTTPStatus.FORBIDDEN)
                return self._json({"admin_session": app_state.create_admin_session_token()})
            if self.path == "/api/telemetry/cart-slot":
                data = self._read_json()
                slot_name = str(data.get("slot", ""))
                customer = str(data.get("customer_id", "guest"))
                app_state.telemetry_cart_slot(slot_name, customer)
                return self._json({"ok": True})
            if self.path == "/api/telemetry/bill":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                return self._json(app_state.telemetry_bill_total(str(data.get("phone", "")), int(data.get("total_paise", 0))))
            if self.path == "/api/cloud-backup/consent":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                consent = bool(data.get("consent", False))
                app_state.security.set_cloud_backup_consent(consent)
                return self._json({"cloud_backup_consent": consent})
            if self.path in {"/api/cart/add", "/api/search/select"}:
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                customer = str(data.get("customer_id", "guest"))
                raw_item_id = data.get("item_id", 0)
                item_id = int(raw_item_id) if str(raw_item_id).isdigit() else 0
                quantity_delta = float(data.get("quantity_delta", 1))
                barcode = str(data.get("barcode", "")).strip()
                return self._json(app_state.add_to_cart(customer, item_id, quantity_delta=quantity_delta, barcode=barcode))
            if self.path == "/api/cart/quantity":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                customer = str(data.get("customer_id", "guest"))
                item_id = int(data.get("item_id", 0))
                quantity = float(data.get("quantity", 0))
                return self._json(app_state.update_cart_quantity(customer, item_id, quantity))
            if self.path == "/api/sales/record":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                customer = str(data.get("customer_id", "guest"))
                payment_method = str(data.get("payment_method", "CASH")).upper()
                result = app_state.record_sale(int(data.get("item_id", 0)), float(data.get("qty", 0)), customer, payment_method=payment_method, collected_cents=data.get("collected_cents"))
                return self._json(result)
            if self.path == "/api/ledger/add":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                phone = str(data.get("phone", ""))
                amount_cents = int(data.get("amount_cents", 0))
                result = app_state.add_ledger_entry(phone, amount_cents)
                return self._json(result, status=200 if result.get("success") else 400)
            if self.path == "/api/day/close-shop":
                if app_state._is_access_locked(auth_header):
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.close_shop())
            self.send_error(404)

    return Handler
