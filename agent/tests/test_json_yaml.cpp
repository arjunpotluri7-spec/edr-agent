#include <gtest/gtest.h>

#include <string>
#include <variant>

#include "edr/json.hpp"
#include "edr/yaml.hpp"

namespace edr {
namespace {

json::Value yaml_ok(const std::string& text) {
  auto v = yaml::parse(text);
  if (auto* e = std::get_if<yaml::ParseError>(&v)) {
    ADD_FAILURE() << "line " << e->line << ": " << e->message;
    return json::Value();
  }
  return std::get<json::Value>(v);
}

std::string yaml_error(const std::string& text) {
  auto v = yaml::parse(text);
  if (auto* e = std::get_if<yaml::ParseError>(&v)) {
    return e->message;
  }
  ADD_FAILURE() << "expected a YAML error for: " << text;
  return "";
}

TEST(Json, RoundTripsNestedValues) {
  const std::string text =
      R"({"a":1,"b":[true,null,"x\n\"y\""],"c":{"d":-2.5},"e":"\u00e9\ud83d\ude00"})";
  auto v = json::parse(text);
  ASSERT_TRUE(std::holds_alternative<json::Value>(v));
  const json::Value& val = std::get<json::Value>(v);
  EXPECT_EQ(val.find("a")->as_int(), 1);
  EXPECT_EQ(val.find("c")->find("d")->as_double(), -2.5);
  EXPECT_EQ(val.find("e")->as_string(), "\xC3\xA9\xF0\x9F\x98\x80");
  auto again = json::parse(json::dump(val));
  ASSERT_TRUE(std::holds_alternative<json::Value>(again));
  EXPECT_EQ(std::get<json::Value>(again), val);
}

TEST(Json, RejectsMalformedInput) {
  for (const char* bad :
       {"{", "[1,]", "{\"a\" 1}", "01", "\"\\ud800\"", "\"a\nb\"", "tru", "1 2", "{\"a\":1,}"}) {
    EXPECT_TRUE(std::holds_alternative<json::ParseError>(json::parse(bad))) << bad;
  }
}

TEST(Json, LimitsDepth) {
  std::string deep(100, '[');
  deep += std::string(100, ']');
  EXPECT_TRUE(std::holds_alternative<json::ParseError>(json::parse(deep)));
}

TEST(Json, EscapesControlCharacters) {
  EXPECT_EQ(json::quote(std::string("a\x01"
                                    "b\\",
                                    4)),
            "\"a\\u0001b\\\\\"");
}

TEST(Yaml, ParsesMappingsSequencesAndFlowLists) {
  const json::Value v = yaml_ok(
      "# comment\n"
      "id: demo-rule   # trailing comment\n"
      "attack: [T1059.001, 'T1027']\n"
      "points: 30\n"
      "ratio: 1.25\n"
      "enabled: true\n"
      "empty:\n"
      "condition:\n"
      "  all:\n"
      "    - field: image\n"
      "      endswith: '\\powershell.exe'\n"
      "    - not:\n"
      "        field: dest_ip\n"
      "        cidr: [10.0.0.0/8, '::1/128']\n"
      "list:\n"
      "- a\n"
      "- \"b\\tc\"\n");
  EXPECT_EQ(v.find("id")->as_string(), "demo-rule");
  EXPECT_EQ(v.find("attack")->as_array().at(0).as_string(), "T1059.001");
  EXPECT_EQ(v.find("points")->as_int(), 30);
  EXPECT_DOUBLE_EQ(v.find("ratio")->as_double(), 1.25);
  EXPECT_TRUE(v.find("enabled")->as_bool());
  EXPECT_TRUE(v.find("empty")->is_null());
  const auto& all = v.find("condition")->find("all")->as_array();
  ASSERT_EQ(all.size(), 2U);
  EXPECT_EQ(all[0].find("endswith")->as_string(), "\\powershell.exe");
  EXPECT_EQ(all[1].find("not")->find("cidr")->as_array().at(1).as_string(), "::1/128");
  EXPECT_EQ(v.find("list")->as_array().at(1).as_string(), "b\tc");
}

TEST(Yaml, SingleQuotesKeepBackslashesAndDoubleQuotes) {
  const json::Value v = yaml_ok("a: 'it''s C:\\x # not a comment'\n");
  EXPECT_EQ(v.find("a")->as_string(), "it's C:\\x # not a comment");
}

TEST(Yaml, RejectsSurprisingYaml11Scalars) {
  for (const char* bad : {"a: yes\n", "a: off\n", "a: 0x10\n", "a: 012\n", "a: 1:30\n",
                          "a: 2026-10-20\n", "a: .5\n", "a: .inf\n", "a: 1_000\n"}) {
    EXPECT_NE(yaml_error(bad).find("quote"), std::string::npos) << bad;
  }
}

TEST(Yaml, RejectsUnsupportedSyntax) {
  EXPECT_NE(yaml_error("a: &x 1\n").find("unsupported"), std::string::npos);
  EXPECT_NE(yaml_error("a: |\n  text\n").find("unsupported"), std::string::npos);
  EXPECT_NE(yaml_error("a: {b: 1}\n").find("unsupported"), std::string::npos);
  EXPECT_NE(yaml_error("a: 1\na: 2\n").find("duplicate"), std::string::npos);
  EXPECT_NE(yaml_error("a:\n\t- b\n").find("tab"), std::string::npos);
  EXPECT_NE(yaml_error("a: 1\n---\nb: 2\n").find("multiple"), std::string::npos);
  EXPECT_NE(yaml_error("a: 'open\n").find("unterminated"), std::string::npos);
  EXPECT_NE(yaml_error("a: [1, [2]]\n").find("nested"), std::string::npos);
}

TEST(Yaml, ReportsLineNumbers) {
  auto v = yaml::parse("a: 1\nb: 2\nc: yes\n");
  ASSERT_TRUE(std::holds_alternative<yaml::ParseError>(v));
  EXPECT_EQ(std::get<yaml::ParseError>(v).line, 3U);
}

}  // namespace
}  // namespace edr
