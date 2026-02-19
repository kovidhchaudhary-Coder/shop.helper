#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace inferno {

enum class Type {
    FIXED,
    VARIABLE,
};

struct InventoryItem {
    int id;
    std::string name;
    Type type;
    double quantity;
    double purchase_price;
    double selling_price;
    bool is_perishable;
    int days_to_rot;
};

class InventoryEngine {
public:
    void addItem(const InventoryItem& item);
    void reserveItems(std::size_t expected_count);
    std::optional<InventoryItem> getItem(int id) const;

    std::string checkRotAlerts(int current_day) const;
    std::string getFuzzyMatch(const std::string& query, int max_results = 8) const;
    std::string recordSale(int id, double qty);
    std::string getMonthlyReport() const;
    std::string getSystemHealthBackup(int total_customer_count) const;

    void upsert_item(const InventoryItem& item) { addItem(item); }
    std::string export_analytics_json(std::size_t top_n = 5) const;

private:
    std::unordered_map<int, InventoryItem> items_;
    std::unordered_map<int, double> sold_qty_;
    double total_income_ = 0.0;
    double total_profit_ = 0.0;
    double total_loss_ = 0.0;
};

}
