#include "inventory_engine.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <vector>

namespace inferno {
namespace {

bool is_whole(double value) {
    return std::fabs(value - std::round(value)) < 1e-9;
}

std::string esc(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        switch (c) {
            case '"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c) << std::nouppercase << std::dec;
                } else {
                    out << static_cast<char>(c);
                }
                break;
        }
    }
    return out.str();
}

std::string to_lower_copy(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (unsigned char c : input) {
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

bool all_digits(const std::string& input) {
    if (input.empty()) return false;
    return std::all_of(input.begin(), input.end(), [](unsigned char c) { return std::isdigit(c); });
}

int levenshtein_bounded(const std::string& left, const std::string& right, int max_distance) {
    const std::size_t n = left.size();
    const std::size_t m = right.size();
    if (n == 0) return static_cast<int>(m);
    if (m == 0) return static_cast<int>(n);

    if (std::abs(static_cast<int>(n) - static_cast<int>(m)) > max_distance) {
        return max_distance + 1;
    }

    std::vector<int> prev(m + 1), cur(m + 1);
    for (std::size_t j = 0; j <= m; ++j) prev[j] = static_cast<int>(j);

    for (std::size_t i = 1; i <= n; ++i) {
        cur[0] = static_cast<int>(i);
        int row_best = cur[0];
        for (std::size_t j = 1; j <= m; ++j) {
            const int cost = (left[i - 1] == right[j - 1]) ? 0 : 1;
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
            row_best = std::min(row_best, cur[j]);
        }
        if (row_best > max_distance) return max_distance + 1;
        prev.swap(cur);
    }
    return prev[m];
}

int levenshtein(const std::string& left, const std::string& right) {
    const std::size_t n = left.size();
    const std::size_t m = right.size();
    if (n == 0) return static_cast<int>(m);
    if (m == 0) return static_cast<int>(n);

    std::vector<int> prev(m + 1), cur(m + 1);
    for (std::size_t j = 0; j <= m; ++j) {
        prev[j] = static_cast<int>(j);
    }

    for (std::size_t i = 1; i <= n; ++i) {
        cur[0] = static_cast<int>(i);
        for (std::size_t j = 1; j <= m; ++j) {
            const int cost = (std::tolower(static_cast<unsigned char>(left[i - 1])) ==
                              std::tolower(static_cast<unsigned char>(right[j - 1])))
                                 ? 0
                                 : 1;
            cur[j] = std::min({
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + cost,
            });
        }
        prev.swap(cur);
    }
    return prev[m];
}

}

void InventoryEngine::addItem(const InventoryItem& item) {
    items_[item.id] = item;
}

void InventoryEngine::reserveItems(std::size_t expected_count) {
    if (expected_count > items_.bucket_count()) {
        items_.reserve(expected_count);
    }
}

std::optional<InventoryItem> InventoryEngine::getItem(int id) const {
    const auto it = items_.find(id);
    if (it == items_.end()) return std::nullopt;
    return it->second;
}

std::string InventoryEngine::checkRotAlerts(int current_day) const {
    std::ostringstream json;
    json << "[";
    bool first = true;

    for (const auto& [_, item] : items_) {
        if (!item.is_perishable) continue;
        const int days_left = item.days_to_rot - current_day;
        if (days_left <= 2) {
            if (!first) json << ",";
            first = false;
            json << "{\"id\":" << item.id
                 << ",\"name\":\"" << esc(item.name)
                 << "\",\"days_left\":" << days_left
                 << ",\"suggested_discount\":\"50%\"}";
        }
    }

    json << "]";
    return json.str();
}

std::string InventoryEngine::getFuzzyMatch(const std::string& query, int max_results) const {
    struct Candidate {
        int distance;
        InventoryItem item;
        double fuzzy_score;
    };

    const std::string normalized_query = to_lower_copy(query);
    if (normalized_query.empty()) return "[]";

    if (all_digits(normalized_query)) {
        try {
            const int id = std::stoi(normalized_query);
            auto exact = getItem(id);
            if (exact.has_value()) {
                std::ostringstream json;
                json << std::fixed << std::setprecision(6)
                     << "[{\"id\":" << exact->id
                     << ",\"name\":\"" << esc(exact->name)
                     << "\",\"quantity\":" << exact->quantity
                     << ",\"fuzzy_distance\":0,\"fuzzy_score\":1.000000}]";
                return json.str();
            }
        } catch (...) {
        }
    }

    std::vector<Candidate> candidates;
    candidates.reserve(items_.size());
    const int max_distance = std::max(2, static_cast<int>(normalized_query.size()));

    for (const auto& [_, item] : items_) {
        const std::string normalized_name = to_lower_copy(item.name);
        int distance = 0;
        double fuzzy_score = 0.0;

        if (normalized_name == normalized_query) {
            distance = 0;
            fuzzy_score = 1.0;
        } else if (normalized_name.rfind(normalized_query, 0) == 0) {
            distance = 1;
            fuzzy_score = 0.975;
        } else if (normalized_name.find(normalized_query) != std::string::npos) {
            distance = 2;
            fuzzy_score = 0.935;
        } else {
            distance = levenshtein_bounded(normalized_query, normalized_name, max_distance);
            const int normalizer = std::max<int>(1, std::max(normalized_query.size(), normalized_name.size()));
            fuzzy_score = 1.0 - (static_cast<double>(distance) / static_cast<double>(normalizer));
        }

        if (distance <= max_distance + 1) {
            candidates.push_back({distance, item, std::max(0.0, fuzzy_score)});
        }
    }

    std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
        if (a.distance != b.distance) return a.distance < b.distance;
        if (std::fabs(a.fuzzy_score - b.fuzzy_score) > 1e-6) return a.fuzzy_score > b.fuzzy_score;
        return a.item.name < b.item.name;
    });

    if (max_results > 0 && static_cast<int>(candidates.size()) > max_results) {
        candidates.resize(static_cast<std::size_t>(max_results));
    }

    std::ostringstream json;
    json << "[";
    for (std::size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];
        json << std::fixed << std::setprecision(6)
             << "{\"id\":" << c.item.id
             << ",\"name\":\"" << esc(c.item.name)
             << "\",\"quantity\":" << c.item.quantity
             << ",\"fuzzy_distance\":" << c.distance
             << ",\"fuzzy_score\":" << c.fuzzy_score << "}";
        if (i + 1 < candidates.size()) json << ",";
    }
    json << "]";
    return json.str();
}

std::string InventoryEngine::recordSale(int id, double qty) {
    auto it = items_.find(id);
    if (it == items_.end()) {
        return "{\"success\":false,\"error\":\"Item not found\"}";
    }

    InventoryItem& item = it->second;
    if (qty <= 0.0) {
        return "{\"success\":false,\"error\":\"Quantity must be positive\"}";
    }

    if (item.type == Type::FIXED && !is_whole(qty)) {
        return "{\"success\":false,\"error\":\"FIXED item requires whole quantity\"}";
    }

    if (item.quantity < qty) {
        return "{\"success\":false,\"error\":\"Insufficient stock\"}";
    }

    item.quantity -= qty;
    if (item.type == Type::FIXED) {
        item.quantity = std::round(item.quantity);
    }

    const double sale_value = item.selling_price * qty;
    const double cost_value = item.purchase_price * qty;
    const double profit = sale_value - cost_value;

    sold_qty_[id] += qty;
    total_income_ += sale_value;
    if (profit >= 0.0) total_profit_ += profit;
    else total_loss_ += std::fabs(profit);

    std::ostringstream out;
    out << std::fixed << std::setprecision(6)
        << "{\"success\":true,\"remaining_stock\":" << item.quantity
        << ",\"profit\":" << profit << "}";
    return out.str();
}

std::string InventoryEngine::getMonthlyReport() const {
    double total_investment = 0.0;
    for (const auto& [_, item] : items_) {
        total_investment += item.quantity * item.purchase_price;
    }

    std::ostringstream out;
    out << std::fixed << std::setprecision(6)
        << "{\"total_investment\":" << total_investment
        << ",\"total_income\":" << total_income_
        << ",\"total_profit\":" << total_profit_
        << ",\"total_loss\":" << total_loss_ << "}";
    return out.str();
}

std::string InventoryEngine::getSystemHealthBackup(int total_customer_count) const {
    struct MarginItem {
        int id;
        std::string name;
        double margin;
        double sold_qty;
    };

    std::vector<MarginItem> margins;
    margins.reserve(items_.size());
    for (const auto& [id, item] : items_) {
        const double margin = item.selling_price - item.purchase_price;
        const auto sold = sold_qty_.find(id);
        const double sold_qty = sold == sold_qty_.end() ? 0.0 : sold->second;
        margins.push_back({id, item.name, margin, sold_qty});
    }

    std::sort(margins.begin(), margins.end(), [](const MarginItem& a, const MarginItem& b) {
        if (a.margin != b.margin) return a.margin > b.margin;
        return a.name < b.name;
    });

    if (margins.size() > 5) margins.resize(5);

    std::ostringstream out;
    out << std::fixed << std::setprecision(6)
        << "{\"monthly_profit\":" << total_profit_
        << ",\"total_customer_count\":" << total_customer_count
        << ",\"top_margin_items\":[";

    for (std::size_t i = 0; i < margins.size(); ++i) {
        const auto& m = margins[i];
        out << "{\"id\":" << m.id
            << ",\"name\":\"" << esc(m.name)
            << "\",\"margin\":" << m.margin
            << ",\"sold_qty\":" << m.sold_qty << "}";
        if (i + 1 < margins.size()) out << ",";
    }

    out << "]}";
    return out.str();
}

std::string InventoryEngine::export_analytics_json(std::size_t) const {
    return getMonthlyReport();
}

}
