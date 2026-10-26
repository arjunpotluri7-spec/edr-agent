#include <gtest/gtest.h>

#include "edr/netutil.hpp"

namespace edr {
namespace {

TEST(Ip, ParsesV4AndV6) {
  EXPECT_TRUE(parse_ip("203.0.113.50").has_value());
  EXPECT_TRUE(parse_ip("::1").has_value());
  EXPECT_TRUE(parse_ip("2001:db8::10").has_value());
  EXPECT_TRUE(parse_ip("::ffff:192.0.2.1").has_value());
  EXPECT_TRUE(parse_ip("1:2:3:4:5:6:7:8").has_value());
  for (const char* bad : {"", "1.2.3", "1.2.3.256", "01.2.3.4", "1.2.3.4.5", "1:2:3:4:5:6:7:8:9",
                          "1::2::3", "fe80::1%eth0", "example.com", ":1:2"}) {
    EXPECT_FALSE(parse_ip(bad).has_value()) << bad;
  }
}

TEST(Cidr, MatchesWithinPrefix) {
  const auto net = parse_cidr("192.0.2.0/24");
  ASSERT_TRUE(net.has_value());
  EXPECT_TRUE(cidr_contains(*net, *parse_ip("192.0.2.80")));
  EXPECT_FALSE(cidr_contains(*net, *parse_ip("192.0.3.1")));
  const auto v6 = parse_cidr("fc00::/7");
  EXPECT_TRUE(cidr_contains(*v6, *parse_ip("fd12::1")));
  EXPECT_FALSE(cidr_contains(*v6, *parse_ip("2001:db8::1")));
  EXPECT_FALSE(cidr_contains(*net, *parse_ip("::1")));  // family mismatch
  const auto host = parse_cidr("10.1.2.3");
  EXPECT_TRUE(cidr_contains(*host, *parse_ip("10.1.2.3")));
  EXPECT_FALSE(parse_cidr("10.0.0.0/33").has_value());
  EXPECT_FALSE(parse_cidr("10.0.0.0/-1").has_value());
}

TEST(Entropy, RandomLabelsScoreHigherThanWords) {
  EXPECT_DOUBLE_EQ(shannon_entropy("aaaa"), 0.0);
  EXPECT_DOUBLE_EQ(shannon_entropy("a8f3kq9z7x2m4v1b"), 4.0);
  EXPECT_LT(shannon_entropy("update-check"), 3.7);
  EXPECT_EQ(longest_label("a8f3kq9z7x2m4v1b.cdn.example.net"), "a8f3kq9z7x2m4v1b");
  EXPECT_EQ(longest_label("abc.def"), "abc");  // first on ties
}

}  // namespace
}  // namespace edr
