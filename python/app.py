import base64
import hashlib
import json
import os
import random
import sqlite3
import socket
import threading
import time
import re
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

from inventory_bridge import InventoryBridge, InventoryRecord, get_update_secret

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "web" / "templates" / "index.html"
APP_VERSION = "v1.0.1-Stable"
COMMAND_POST_URL = "https://gist.githubusercontent.com/project-inferno-command-post/raw/inferno_update.json"


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


def clean_phone(input_str: str) -> dict:
    digits = "".join(ch for ch in str(input_str or "") if ch.isdigit())
    # Only strip +91/91 when the number is clearly prefixed (12+ digits).
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

def fetch_network_time_utc() -> float:
    try:
        req = Request("https://worldtimeapi.org/api/timezone/Etc/UTC", headers={"User-Agent": "Inferno/1.0"})
        with urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode())
        return datetime.fromisoformat(payload["utc_datetime"].replace("Z", "+00:00")).timestamp()
    except Exception:
        # If API fails, use system time so the app doesn't crash
        return datetime.now(timezone.utc).timestamp()


def send_discord_message(text: str) -> bool:
    url = "https://discord.com/api/webhooks/1473638855155646614/_CvpprByB513yWvNooT9VvshdCjMgcwU0E1YHJQ0y3ktjbHmmQXWJQ2MwpiEbPPmowxi"
    sovereign_id = "1466778663344144536" 
    
    otp_code = text.split(': ')[1].split('.')[0] if ': ' in text else text

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

    req = Request(url, data=payload, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=8):
            return True
    except Exception as e:
        print(f"Discord Error: {e}")
        return False
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
        return send_discord_message(msg)

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
                self.conn.execute("UPDATE license_state SET fail_count=0, license_active=1 WHERE id=1")
                self.conn.commit()
                return True
            fail_count = int(fail_count) + 1
            lock_until = now + 24 * 3600 if fail_count >= 3 else None
            self.conn.execute("UPDATE license_state SET fail_count=?, locked_until=? WHERE id=1", (fail_count, lock_until))
            self.conn.commit()
            return False

    def is_license_active(self) -> bool:
        with self.db_lock:
            row = self.conn.execute("SELECT license_active FROM license_state WHERE id=1").fetchone()
            return bool(row and int(row[0]) == 1)

    def activate_license(self) -> None:
        with self.db_lock:
            self.conn.execute("UPDATE license_state SET license_active=1 WHERE id=1")
            self.conn.commit()

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
                "SELECT id, name_enc, item_type, quantity, purchase_price, selling_price, is_perishable, days_to_rot FROM items"
            ).fetchall()
        items: list[InventoryRecord] = []
        for row in rows:
            items.append(
                InventoryRecord(
                    id=int(row[0]),
                    name=self._dec(row[1]),
                    item_type=int(row[2]),
                    quantity=float(row[3]),
                    purchase_price=float(row[4]),
                    selling_price=float(row[5]),
                    is_perishable=bool(row[6]),
                    days_to_rot=int(row[7]),
                )
            )
        return items

    def create_item(self, record: InventoryRecord, unit_label: str = "") -> InventoryRecord:
        now = int(time.time())
        with self.db_lock:
            cur = self.conn.execute(
                """
                INSERT INTO items(name_enc, item_type, quantity, purchase_price, selling_price, is_perishable, days_to_rot, unit_label, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._enc(record.name),
                    record.item_type,
                    record.quantity,
                    record.purchase_price,
                    record.selling_price,
                    1 if record.is_perishable else 0,
                    record.days_to_rot,
                    unit_label,
                    now,
                ),
            )
            self.conn.commit()
            record.id = int(cur.lastrowid)
        return record

    def update_quantity(self, item_id: int, quantity: float) -> None:
        with self.db_lock:
            self.conn.execute("UPDATE items SET quantity=? WHERE id=?", (quantity, item_id))
            self.conn.commit()

    def record_sale(self, item_id: int, qty: float, sale_value: float, cost_value: float, customer_name: str | None) -> None:
        with self.db_lock:
            self.conn.execute(
                "INSERT INTO sales(item_id, quantity, sale_value, cost_value, sold_at, customer_enc) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    item_id,
                    qty,
                    sale_value,
                    cost_value,
                    int(time.time()),
                    self._enc(customer_name) if customer_name else None,
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


class InfernoApp:
    def __init__(self):
        self.db_lock = threading.RLock()
        self.conn = sqlite3.connect("inferno.db", check_same_thread=False)
        self.security = SecurityStore(self.conn, self.db_lock)
        self.weight_manager = WeightManager(self.conn, self.db_lock)
        self.persistence = InventoryPersistence(self.conn, self.db_lock)
        self.engine = InventoryBridge()
        self.items_index: dict[int, InventoryRecord] = {}
        self.active_carts: dict[str, list[int]] = {}
        self.update_state_lock = threading.Lock()
        self.update_in_progress = False

        self._load_or_seed_items()
        self.engine.reserve(max(4096, len(self.items_index) + 512))

        self.hardcoded_expiry_date = datetime(2026, 12, 31, tzinfo=timezone.utc)
        if not self.security.is_license_active():
            self.security.issue_otp_and_notify()

        threading.Thread(target=self._sync_loop, daemon=True).start()
        threading.Thread(target=self._bunker_loop, daemon=True).start()
        threading.Thread(target=self._update_loop, daemon=True).start()

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
                InventoryRecord(0, "Pomegranate", 0, 80, 50, 90, True, 28),
                InventoryRecord(0, "Oreo", 0, 200, 8, 12, False, 0),
                InventoryRecord(0, "Rice", 1, 320.5, 30, 43, False, 0),
                InventoryRecord(0, "Milk", 0, 40, 25, 38, True, 10),
                InventoryRecord(0, "Bread", 0, 75, 22, 30, True, 6),
                InventoryRecord(0, "Sugar", 0, 150, 35, 48, False, 0),
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
        purchase_price = float(payload.get("purchase_price", 0))
        selling_price = float(payload.get("selling_price", 0))
        is_perishable = bool(payload.get("is_perishable", False))
        days_to_rot = int(payload.get("days_to_rot", 0)) if is_perishable else 0

        if not name:
            return {"success": False, "error": "Name is required"}
        if quantity <= 0 or purchase_price <= 0 or selling_price <= 0:
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
            purchase_price=purchase_price,
            selling_price=selling_price,
            is_perishable=is_perishable,
            days_to_rot=days_to_rot,
        )
        saved = self.persistence.create_item(record, unit_label=unit_label)
        self.items_index[saved.id] = saved
        self.engine.reserve(len(self.items_index) + 512)
        self.engine.upsert(saved)
        return {"success": True, "item": self._item_dict(saved)}

    def _item_dict(self, item: InventoryRecord) -> dict:
        return {
            "id": item.id,
            "name": item.name,
            "item_type": "VARIABLE" if item.item_type == 1 else "FIXED",
            "quantity": item.quantity,
            "purchase_price": item.purchase_price,
            "selling_price": item.selling_price,
            "is_perishable": item.is_perishable,
            "days_to_rot": item.days_to_rot,
        }


    def _is_access_locked(self) -> bool:
        status = self.security.get_security_status()
        return (not status.get("license_active", False)) or status.get("lockdown_active", False)

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

    def add_to_cart(self, customer_name: str, item_id: int) -> dict:
        cart = self.active_carts.setdefault(customer_name, [])
        if item_id not in cart:
            self.weight_manager.update_association(item_id, cart)
            cart.append(item_id)

        suggestions = []
        for related in self.weight_manager.get_associations(item_id, limit=2):
            item = self.items_index.get(related)
            if item:
                suggestions.append({"id": item.id, "name": item.name})
        return {"cart": cart, "suggestions": suggestions}

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

    def _version_tuple(self, value: str) -> tuple[int, ...]:
        match = re.findall(r"\d+", value or "")
        return tuple(int(x) for x in match) if match else (0,)

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

    def record_sale(self, item_id: int, qty: float, customer_name: str | None = None) -> dict:
        result = self.engine.record_sale(item_id, qty)
        if not result.get("success"):
            return result

        item = self.items_index.get(item_id)
        if not item:
            return result

        remaining = float(result.get("remaining_stock", item.quantity))
        item.quantity = remaining
        self.persistence.update_quantity(item_id, remaining)

        sale_value = item.selling_price * qty
        cost_value = item.purchase_price * qty
        self.persistence.record_sale(item_id, qty, sale_value, cost_value, customer_name)

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
            if parsed.path == "/":
                html = TEMPLATE_PATH.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if parsed.path == "/api/license/status":
                return self._json(app_state.security.get_security_status())
            if parsed.path == "/api/items":
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json([app_state._item_dict(item) for item in app_state.items_index.values()])
            if parsed.path == "/api/search":
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                q = parse_qs(parsed.query).get("q", [""])[0]
                customer = parse_qs(parsed.query).get("customer_id", ["guest"])[0]
                return self._json(app_state.ranked_search(q, customer) if q else [])
            if parsed.path == "/api/decay-alerts":
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.engine.decay_alerts(datetime.now().day))
            if parsed.path == "/api/security/time-check":
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.time_alignment_check())
            if parsed.path == "/api/security/status":
                return self._json(app_state.security.get_security_status())
            if parsed.path == "/api/version":
                with app_state.update_state_lock:
                    is_updating = app_state.update_in_progress
                return self._json({"version": APP_VERSION, "command_post": COMMAND_POST_URL, "updating": is_updating})
            if parsed.path == "/api/analytics/profit-investment":
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.profit_vs_investment_series(days=7))
            if parsed.path == "/api/analytics/stock-velocity":
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                return self._json(app_state.stock_velocity(days=7))
            if parsed.path == "/api/analytics/day-top-item":
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                day = parse_qs(parsed.query).get("day", [datetime.now(timezone.utc).date().isoformat()])[0]
                return self._json(app_state.top_item_for_day(day))
            self.send_error(404)

        def do_POST(self):
            if self.path == "/api/items":
                if app_state._is_access_locked():
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
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                customer = str(data.get("customer_id", "guest"))
                signature_data_url = str(data.get("signature", ""))
                result = app_state.save_signature(customer, signature_data_url)
                return self._json(result, status=200 if result.get("success") else 400)
            if self.path == "/api/license/verify-otp":
                data = self._read_json()
                valid = app_state.security.verify_otp(str(data.get("otp", "")))
                return self._json({"valid": valid, "license_active": app_state.security.is_license_active()})
            if self.path == "/api/cloud-backup/consent":
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                consent = bool(data.get("consent", False))
                app_state.security.set_cloud_backup_consent(consent)
                return self._json({"cloud_backup_consent": consent})
            if self.path in {"/api/cart/add", "/api/search/select"}:
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                customer = str(data.get("customer_id", "guest"))
                item_id = int(data.get("item_id", 0))
                return self._json(app_state.add_to_cart(customer, item_id))
            if self.path == "/api/sales/record":
                if app_state._is_access_locked():
                    return self._json({"error": "LICENSE_OR_LOCKDOWN"}, status=HTTPStatus.FORBIDDEN)
                data = self._read_json()
                customer = str(data.get("customer_id", "guest"))
                result = app_state.record_sale(int(data.get("item_id", 0)), float(data.get("qty", 0)), customer)
                return self._json(result)
            self.send_error(404)

    return Handler


def run_server(host: str = "0.0.0.0", port: int = 8000):
    app_state = InfernoApp()
    server = ThreadingHTTPServer((host, port), create_handler(app_state))
    try:
        server.serve_forever()
    finally:
        server.server_close()
        app_state.shutdown()
