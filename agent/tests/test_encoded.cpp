#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "edr/encoded_command.hpp"

namespace edr {
namespace {

// UTF-16LE Base64 of: Write-Output 'edr-agent demo: simulated download cradle'
constexpr const char* kDemo =
    "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGUAZAByAC0AYQBnAGUAbgB0ACAAZABlAG0AbwA6ACAAcwBpAG0AdQBsAG"
    "EA"
    "dABlAGQAIABkAG8AdwBuAGwAbwBhAGQAIABjAHIAYQBkAGwAZQAnAA==";

TEST(EncodedCommand, DecodesTheDemoPayload) {
  const auto r =
      decode_encoded_command(std::string("powershell.exe -NoProfile -EncodedCommand ") + kDemo);
  EXPECT_TRUE(r.found);
  ASSERT_TRUE(r.text.has_value());
  EXPECT_EQ(*r.text, "Write-Output 'edr-agent demo: simulated download cradle'");
}

TEST(EncodedCommand, AcceptsEveryPrefixOfTheFlagAnyCase) {
  for (const char* flag :
       {"-e", "-ec", "-en", "-enc", "-ENC", "-EncodedCommand", "/enc", "-encodedc"}) {
    EXPECT_TRUE(is_encoded_flag(flag)) << flag;
  }
  for (const char* other :
       {"-", "-ex", "-ExecutionPolicy", "-encodedcommandx", "enc", "-f", "--enc"}) {
    EXPECT_FALSE(is_encoded_flag(other)) << other;
  }
}

TEST(EncodedCommand, QuotedPayloadAndPaddingVariants) {
  // "hi" in UTF-16LE is 68 00 69 00 -> "aABpAA==" (and "aABpAA" without padding).
  EXPECT_EQ(*decode_encoded_command("pwsh -enc \"aABpAA==\"").text, "hi");
  EXPECT_EQ(*decode_encoded_command("pwsh -enc aABpAA").text, "hi");
}

TEST(EncodedCommand, MalformedInputIsReportedNotDecoded) {
  EXPECT_EQ(*decode_encoded_command("powershell -enc").error, "missing payload");
  EXPECT_EQ(*decode_encoded_command("powershell -enc not*base64!").error, "invalid base64");
  EXPECT_EQ(*decode_encoded_command("powershell -enc aGkh").error,
            "invalid utf-16le");  // odd bytes
  EXPECT_EQ(*decode_encoded_command("powershell -enc AAA=").error, "invalid utf-16le");  // NUL
  EXPECT_EQ(*decode_encoded_command("powershell -enc ANg=").error,
            "invalid utf-16le");  // lone surrogate
  EXPECT_EQ(*decode_encoded_command("powershell -enc QQ=").error, "invalid base64");  // bad padding
  EXPECT_EQ(*decode_encoded_command("powershell -enc Q").error, "invalid base64");    // 1 char
  EXPECT_EQ(*decode_encoded_command("powershell -enc QQ==QQ==").error, "invalid base64");
  const std::string huge = "powershell -enc " + std::string(kMaxEncodedPayload + 4, 'A');
  EXPECT_EQ(*decode_encoded_command(huge).error, "payload too large");
}

TEST(EncodedCommand, NoFlagMeansNotFound) {
  const auto r = decode_encoded_command("powershell.exe -NoProfile -File C:\\x.ps1");
  EXPECT_FALSE(r.found);
  EXPECT_FALSE(r.text.has_value());
  EXPECT_FALSE(r.error.has_value());
}

TEST(EncodedCommand, SurrogatePairsBecomeUtf8) {
  // U+1F600 = D83D DE00 -> bytes 3D D8 00 DE -> Base64 "PdgA3g=="
  EXPECT_EQ(*decode_encoded_command("pwsh -e PdgA3g==").text, "\xF0\x9F\x98\x80");
}

TEST(Base64, StrictAlphabet) {
  EXPECT_FALSE(base64_decode("ab-_").has_value());  // URL-safe alphabet is not accepted
  EXPECT_FALSE(base64_decode("").has_value());
  EXPECT_EQ(base64_decode("TWFu")->size(), 3U);
}

TEST(CommandLine, SplitsWithQuotes) {
  const auto t = split_command_line("\"C:\\Program Files\\a.exe\"  -x \"two words\"\t-y");
  ASSERT_EQ(t.size(), 4U);
  EXPECT_EQ(t[0], "C:\\Program Files\\a.exe");
  EXPECT_EQ(t[2], "two words");
}

}  // namespace
}  // namespace edr
