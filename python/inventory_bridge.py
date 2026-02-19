import ctypes
import base64
import json
import os
from dataclasses import dataclass
from typing import List


_OBFUSCATED_UPDATE_SECRET_B64 = "YV5fVEJYWVFfYkNOSV5XRm9ERl5fSEQ="
_OBFUSCATION_MASK = 12


def get_update_secret() -> str:
    env_value = os.environ.get("INFERNO_UPDATE_SECRET", "").strip()
    if env_value:
        return env_value
    raw = base64.b64decode(_OBFUSCATED_UPDATE_SECRET_B64.encode("utf-8"))
    return "".join(chr(b ^ _OBFUSCATION_MASK) for b in raw)


@dataclass
class InventoryRecord:
    id: int
    name: str
    item_type: int
    quantity: float
    purchase_price: float
    selling_price: float
    is_perishable: bool
    days_to_rot: int
    purchase_date: str = ""


class NativeEngineError(RuntimeError):
    pass


class InventoryBridge:
    def __init__(self, lib_path: str = "./build/libinferno.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"C++ extension not found at {lib_path}")
        self.lib = ctypes.CDLL(lib_path)

        self.lib.inferno_engine_create.restype = ctypes.c_void_p
        self.lib.inferno_engine_destroy.argtypes = [ctypes.c_void_p]
        self.lib.inferno_engine_reserve.argtypes = [ctypes.c_void_p, ctypes.c_int]

        self.lib.inferno_add_item.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_double,
            ctypes.c_double,
            ctypes.c_double,
            ctypes.c_int,
            ctypes.c_int,
        ]
        self.lib.inferno_check_rot_alerts.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.inferno_check_rot_alerts.restype = ctypes.c_void_p
        self.lib.inferno_get_fuzzy_match.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
        self.lib.inferno_get_fuzzy_match.restype = ctypes.c_void_p
        self.lib.inferno_record_sale.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_double]
        self.lib.inferno_record_sale.restype = ctypes.c_void_p
        self.lib.inferno_get_monthly_report.argtypes = [ctypes.c_void_p]
        self.lib.inferno_get_monthly_report.restype = ctypes.c_void_p
        self.lib.inferno_get_system_health_backup.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.inferno_get_system_health_backup.restype = ctypes.c_void_p
        self.lib.inferno_engine_free_string.argtypes = [ctypes.c_void_p]

        self.handle = self.lib.inferno_engine_create()
        if not self.handle:
            raise NativeEngineError("inferno_engine_create returned null handle")
        self._closed = False

    def shutdown(self) -> None:
        if self._closed:
            return
        if self.handle:
            self.lib.inferno_engine_destroy(self.handle)
            self.handle = None
        self._closed = True

    def close(self) -> None:
        self.shutdown()

    def __del__(self):
        try:
            self.shutdown()
        except Exception:
            pass

    def _free_native_ptr(self, ptr) -> None:
        if ptr:
            self.lib.inferno_engine_free_string(ptr)

    def _consume_json_ptr(self, ptr) -> list | dict:
        if not ptr:
            return {}
        try:
            c_value = ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8")
            return json.loads(c_value)
        finally:
            self._free_native_ptr(ptr)

    def reserve(self, expected_count: int) -> None:
        self.lib.inferno_engine_reserve(self.handle, ctypes.c_int(expected_count))

    def upsert(self, record: InventoryRecord) -> None:
        self.lib.inferno_add_item(
            self.handle,
            record.id,
            record.name.encode(),
            record.item_type,
            ctypes.c_double(record.quantity),
            ctypes.c_double(record.purchase_price),
            ctypes.c_double(record.selling_price),
            1 if record.is_perishable else 0,
            record.days_to_rot,
        )

    def search(self, query: str, max_results: int = 10) -> List[dict]:
        ptr = self.lib.inferno_get_fuzzy_match(self.handle, query.encode(), max_results)
        return self._consume_json_ptr(ptr)

    def decay_alerts(self, current_day: int) -> List[dict]:
        ptr = self.lib.inferno_check_rot_alerts(self.handle, current_day)
        return self._consume_json_ptr(ptr)

    def record_sale(self, item_id: int, qty: float) -> dict:
        ptr = self.lib.inferno_record_sale(self.handle, item_id, ctypes.c_double(qty))
        return self._consume_json_ptr(ptr)

    def analytics(self) -> dict:
        ptr = self.lib.inferno_get_monthly_report(self.handle)
        return self._consume_json_ptr(ptr)

    def system_health_backup(self, total_customer_count: int) -> dict:
        ptr = self.lib.inferno_get_system_health_backup(self.handle, total_customer_count)
        return self._consume_json_ptr(ptr)
