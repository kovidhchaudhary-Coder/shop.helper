#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef void* InfernoEngineHandle;

InfernoEngineHandle inferno_engine_create();
void inferno_engine_destroy(InfernoEngineHandle handle);
void inferno_engine_reserve(InfernoEngineHandle handle, int expected_count);

void inferno_add_item(
    InfernoEngineHandle handle,
    int id,
    const char* name,
    int item_type,
    double quantity,
    double purchase_price,
    double selling_price,
    int is_perishable,
    int days_to_rot);

const char* inferno_check_rot_alerts(InfernoEngineHandle handle, int current_day);
const char* inferno_get_fuzzy_match(InfernoEngineHandle handle, const char* query, int max_results);
const char* inferno_record_sale(InfernoEngineHandle handle, int id, double qty);
const char* inferno_get_monthly_report(InfernoEngineHandle handle);
const char* inferno_get_system_health_backup(InfernoEngineHandle handle, int total_customer_count);

// Backward-compatible aliases used by existing Python bridge
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
    const char* purchase_date);
const char* inferno_engine_search_json(InfernoEngineHandle handle, const char* query, int max_results);
const char* inferno_engine_decay_json(InfernoEngineHandle handle, const char* current_date);
const char* inferno_engine_analytics_json(InfernoEngineHandle handle, int top_n);

void inferno_engine_free_string(const char* value);

#ifdef __cplusplus
}
#endif
