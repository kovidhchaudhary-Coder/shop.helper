# shop.helper — Project Inferno Bootstrap

Project Inferno includes a C++ inventory core, Python app layer, local SQLite persistence, OTP license gate, bunker expiry lockdown, and a dark-mode Chart.js dashboard.

## C++ Core (Finalized)
- `InventoryItem` uses:
  - `int id`, `std::string name`
  - `enum Type { FIXED, VARIABLE }`
  - **`double`** `quantity`, `purchase_price`, `selling_price`
  - `bool is_perishable`, `int days_to_rot`
- `std::unordered_map<int, InventoryItem>` store for O(1)-average access.
- Dynamic scaling via `reserveItems(expected_count)`.
- Full JSON-safe escaping for control characters (`\n`, `\r`, `\t`, etc.) in C++ JSON output.

## C API (`extern "C"`)
- `inferno_engine_reserve`
- `inferno_add_item`
- `inferno_check_rot_alerts`
- `inferno_get_fuzzy_match`
- `inferno_record_sale` (double qty)
- `inferno_get_monthly_report`
- `inferno_get_system_health_backup`

## Revenue Shield (OTP Paywall + Bunker)
- `license_state` in `inferno.db` tracks `license_active`, OTP hash/expiry, warning count, and lockdown state.
- On startup, if `license_active = 0`, backend issues OTP and sends it to owner via Telegram Bot API (`INFERNO_TELEGRAM_BOT_TOKEN`, `INFERNO_TELEGRAM_CHAT_ID`).
- UI is blocked behind OTP screen until `/api/license/verify-otp` succeeds.
- Bunker thread runs every 60 minutes and checks `hardcoded_expiry_date`; on expiry it sets lockdown and UI shows:
  - `RENTAL EXPIRED: CONTACT ARCHITECT`

## Dynamic Inventory + Analytics
- New item creation endpoint: `POST /api/items`
- Profit vs Investment API: `GET /api/analytics/profit-investment`
- Stock Velocity API: `GET /api/analytics/stock-velocity`
- Interactive day top-seller API: `GET /api/analytics/day-top-item`

## Telemetry (Monthly Report)
- On day 30 (with consent + HTTPS webhook + connectivity), backend sends encrypted monthly report payload.
- Report data is sourced from C++ double-precision analytics (`getSystemHealthBackup`).

## Build
```bash
mkdir -p build
g++ -std=c++17 -shared -fPIC cpp/inventory_engine.cpp cpp/inventory_c_api.cpp -Icpp -o build/libinferno.so
python -m py_compile python/main.py python/app.py python/inventory_bridge.py
python python/main.py
```
