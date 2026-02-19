#include "inventory_c_api.h"
#include "inventory_engine.hpp"

#include <cstdlib>
#include <cstring>
#include <string>

using inferno::InventoryEngine;
using inferno::InventoryItem;
using inferno::Type;

namespace {

const char* alloc_string(const std::string& value) {
    char* buf = static_cast<char*>(std::malloc(value.size() + 1));
    std::memcpy(buf, value.c_str(), value.size() + 1);
    return buf;
}

}

extern "C" {

InfernoEngineHandle inferno_engine_create() {
    return new InventoryEngine();
}

void inferno_engine_destroy(InfernoEngineHandle handle) {
    delete static_cast<InventoryEngine*>(handle);
}

void inferno_engine_reserve(InfernoEngineHandle handle, int expected_count) {
    auto* engine = static_cast<InventoryEngine*>(handle);
    if (expected_count > 0) {
        engine->reserveItems(static_cast<std::size_t>(expected_count));
    }
}

void inferno_add_item(
    InfernoEngineHandle handle,
    int id,
    const char* name,
    int item_type,
    double quantity,
    double purchase_price,
    double selling_price,
    int is_perishable,
    int days_to_rot) {
    auto* engine = static_cast<InventoryEngine*>(handle);
    engine->addItem(InventoryItem{
        id,
        name ? name : "",
        item_type == 0 ? Type::FIXED : Type::VARIABLE,
        quantity,
        purchase_price,
        selling_price,
        is_perishable == 1,
        days_to_rot,
    });
}

const char* inferno_check_rot_alerts(InfernoEngineHandle handle, int current_day) {
    auto* engine = static_cast<InventoryEngine*>(handle);
    return alloc_string(engine->checkRotAlerts(current_day));
}

const char* inferno_get_fuzzy_match(InfernoEngineHandle handle, const char* query, int max_results) {
    auto* engine = static_cast<InventoryEngine*>(handle);
    return alloc_string(engine->getFuzzyMatch(query ? query : "", max_results));
}

const char* inferno_record_sale(InfernoEngineHandle handle, int id, double qty) {
    auto* engine = static_cast<InventoryEngine*>(handle);
    return alloc_string(engine->recordSale(id, qty));
}

const char* inferno_get_monthly_report(InfernoEngineHandle handle) {
    auto* engine = static_cast<InventoryEngine*>(handle);
    return alloc_string(engine->getMonthlyReport());
}

const char* inferno_get_system_health_backup(InfernoEngineHandle handle, int total_customer_count) {
    auto* engine = static_cast<InventoryEngine*>(handle);
    return alloc_string(engine->getSystemHealthBackup(total_customer_count));
}

void inferno_engine_upsert(
    InfernoEngineHandle handle,
    int id,
    const char* name,
    int item_type,
    double quantity,
    double purchase_price,
    double selling_price,
    int is_perishable,
    int days_to_rot,
    const char*) {
    inferno_add_item(
        handle,
        id,
        name,
        item_type,
        quantity,
        purchase_price,
        selling_price,
        is_perishable,
        days_to_rot);
}

const char* inferno_engine_search_json(InfernoEngineHandle handle, const char* query, int max_results) {
    return inferno_get_fuzzy_match(handle, query, max_results);
}

const char* inferno_engine_decay_json(InfernoEngineHandle handle, const char*) {
    return inferno_check_rot_alerts(handle, 0);
}

const char* inferno_engine_analytics_json(InfernoEngineHandle handle, int) {
    return inferno_get_monthly_report(handle);
}

void inferno_engine_free_string(const char* value) {
    std::free(const_cast<char*>(value));
}

}
