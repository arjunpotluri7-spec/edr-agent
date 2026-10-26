// Minimal JSON value, parser and writer. Objects keep insertion order so output is stable.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace edr::json {

class Value;
using Array = std::vector<Value>;
using Object = std::vector<std::pair<std::string, Value>>;

class Value {
 public:
  enum class Kind { Null, Bool, Int, Double, String, Array, Object };

  Value() = default;
  Value(std::nullptr_t) {}
  Value(bool b) : data_(b) {}
  Value(int i) : data_(static_cast<std::int64_t>(i)) {}
  Value(std::int64_t i) : data_(i) {}
  Value(double d) : data_(d) {}
  Value(const char* s) : data_(std::string(s)) {}
  Value(std::string s) : data_(std::move(s)) {}
  Value(std::string_view s) : data_(std::string(s)) {}
  Value(Array a) : data_(std::move(a)) {}
  Value(Object o) : data_(std::move(o)) {}

  [[nodiscard]] Kind kind() const { return static_cast<Kind>(data_.index()); }
  [[nodiscard]] bool is_null() const { return kind() == Kind::Null; }
  [[nodiscard]] bool is_bool() const { return kind() == Kind::Bool; }
  [[nodiscard]] bool is_int() const { return kind() == Kind::Int; }
  [[nodiscard]] bool is_number() const { return kind() == Kind::Int || kind() == Kind::Double; }
  [[nodiscard]] bool is_string() const { return kind() == Kind::String; }
  [[nodiscard]] bool is_array() const { return kind() == Kind::Array; }
  [[nodiscard]] bool is_object() const { return kind() == Kind::Object; }

  [[nodiscard]] bool as_bool() const { return std::get<bool>(data_); }
  [[nodiscard]] std::int64_t as_int() const { return std::get<std::int64_t>(data_); }
  [[nodiscard]] double as_double() const {
    return is_int() ? static_cast<double>(as_int()) : std::get<double>(data_);
  }
  [[nodiscard]] const std::string& as_string() const { return std::get<std::string>(data_); }
  [[nodiscard]] const Array& as_array() const { return std::get<Array>(data_); }
  [[nodiscard]] Array& as_array() { return std::get<Array>(data_); }
  [[nodiscard]] const Object& as_object() const { return std::get<Object>(data_); }
  [[nodiscard]] Object& as_object() { return std::get<Object>(data_); }

  // Object lookup; nullptr when this is not an object or the key is absent.
  [[nodiscard]] const Value* find(std::string_view key) const;
  // Appends (or replaces) a key in an object value.
  void set(std::string key, Value value);

  friend bool operator==(const Value& a, const Value& b) { return a.data_ == b.data_; }

 private:
  std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object> data_;
};

struct ParseError {
  std::size_t offset = 0;
  std::string message;
};

// Parses one JSON document (RFC 8259). Depth is limited to 64. Duplicate keys: last wins.
std::variant<Value, ParseError> parse(std::string_view text);

// Compact serialization ({"a":1,"b":[true,null]}); strings are UTF-8 with JSON escapes.
std::string dump(const Value& value);
std::string quote(std::string_view text);

}  // namespace edr::json
