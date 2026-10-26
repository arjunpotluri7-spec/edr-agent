#include <gtest/gtest.h>

#include <string>
#include <variant>

#include "edr/xml.hpp"

namespace edr {
namespace {

TEST(Xml, ParsesElementsAttributesEntitiesAndCdata) {
  auto r = xml::parse(
      "<?xml version='1.0'?><!-- c --><Root a=\"1 &amp; 2\" b='x'><Data Name=\"k\">v "
      "&lt;&#65;&#x42;&gt;"
      "</Data><Empty/><C><![CDATA[<raw & text>]]></C></Root>");
  ASSERT_TRUE(std::holds_alternative<xml::Element>(r));
  const auto& doc = std::get<xml::Element>(r);
  ASSERT_EQ(doc.children.size(), 1U);
  const auto& root = doc.children[0];
  EXPECT_EQ(*root.attribute("a"), "1 & 2");
  EXPECT_EQ(*root.attribute("b"), "x");
  EXPECT_EQ(root.child("Data")->text, "v <AB>");
  EXPECT_NE(root.child("Empty"), nullptr);
  EXPECT_EQ(root.child("C")->text, "<raw & text>");
}

TEST(Xml, AcceptsFragmentsWithSeveralTopLevelElements) {
  auto r = xml::parse("<Event>1</Event>\n<Event>2</Event>\n");
  ASSERT_TRUE(std::holds_alternative<xml::Element>(r));
  EXPECT_EQ(std::get<xml::Element>(r).children.size(), 2U);
}

TEST(Xml, RejectsDoctypeAndMalformedMarkup) {
  for (const char* bad :
       {"<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>", "<a><b></a>", "<a>",
        "<a x=1/>", "<a>&unknown;</a>", "<a>&#0;</a>", "<a>&#xD800;</a>", "text", "<a x=\"<\"/>"}) {
    EXPECT_TRUE(std::holds_alternative<xml::ParseError>(xml::parse(bad))) << bad;
  }
}

TEST(Xml, LimitsDepth) {
  std::string deep;
  for (int i = 0; i < 100; ++i) {
    deep += "<a>";
  }
  for (int i = 0; i < 100; ++i) {
    deep += "</a>";
  }
  EXPECT_TRUE(std::holds_alternative<xml::ParseError>(xml::parse(deep)));
}

}  // namespace
}  // namespace edr
