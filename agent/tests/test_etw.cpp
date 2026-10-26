#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "edr/etw.hpp"
#include "edr/textutil.hpp"

namespace edr {
namespace {

// 2026-10-20T09:15:10.000Z as FILETIME.
constexpr std::int64_t kFiletime = (1792487710000LL * 10000) + 116444736000000000LL;

TEST(Etw, ProcessStartMapsAndConvertsDevicePaths) {
  EtwRecord r;
  r.provider = EtwProvider::KernelProcess;
  r.event_id = 1;
  r.timestamp_filetime = kFiletime;
  r.properties = {
      {"ProcessID", std::uint64_t{5208}},
      {"ParentProcessID", std::uint64_t{4120}},
      {"ImageName", std::string("\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe")}};
  EtwMapContext ctx;
  ctx.host = "WS-TEST-01";
  ctx.device_map = {{"\\Device\\HarddiskVolume3", "C:"}};
  const auto ev = map_etw_record(r, ctx);
  ASSERT_TRUE(ev.has_value());
  EXPECT_EQ(ev->type, EventType::ProcessCreate);
  EXPECT_EQ(ev->pid, 5208);
  EXPECT_EQ(ev->ppid, 4120);
  EXPECT_EQ(ev->image, "C:\\Windows\\System32\\cmd.exe");
  EXPECT_EQ(ev->source, "etw");
  EXPECT_EQ(format_ts(ev->ts_ms), "2026-10-20T09:15:10.000Z");
  EXPECT_EQ(ev->id, "etw-WS-TEST-01-1792487710000-1");
}

TEST(Etw, TcpConnectDecodesNetworkByteOrder) {
  EtwRecord r;
  r.provider = EtwProvider::KernelNetwork;
  r.event_id = 12;
  r.timestamp_filetime = kFiletime;
  // 203.0.113.50 in memory order cb 00 71 32, read as a little-endian UInt32.
  r.properties = {{"PID", std::uint64_t{5208}},
                  {"daddr", std::uint64_t{0x327100CBU}},
                  {"saddr", std::uint64_t{0x29141E0AU}},
                  {"dport", std::uint64_t{0xFB20U}},  // 8443 = 0x20FB, byte-swapped
                  {"sport", std::uint64_t{0xCAC3U}}};
  EtwMapContext ctx;
  ctx.host = "H";
  const auto ev = map_etw_record(r, ctx);
  ASSERT_TRUE(ev.has_value());
  EXPECT_EQ(ev->type, EventType::NetworkConnect);
  EXPECT_EQ(ev->dest_ip, "203.0.113.50");
  EXPECT_EQ(ev->src_ip, "10.30.20.41");
  EXPECT_EQ(ev->dest_port, 8443);
  EXPECT_EQ(ev->src_port, 50122);
  EXPECT_EQ(ev->initiated, true);
}

TEST(Etw, Tcp6AndDnsAndIgnoredEvents) {
  EtwRecord r6;
  r6.provider = EtwProvider::KernelNetwork;
  r6.event_id = 28;
  std::vector<std::uint8_t> addr(16, 0);
  addr[0] = 0x20;
  addr[1] = 0x01;
  addr[2] = 0x0d;
  addr[3] = 0xb8;
  addr[15] = 0x10;
  r6.properties = {{"PID", std::uint64_t{1}}, {"daddr", addr}, {"dport", std::uint64_t{0xBB01U}}};
  EtwMapContext ctx;
  ctx.host = "H";
  const auto ev6 = map_etw_record(r6, ctx);
  ASSERT_TRUE(ev6.has_value());
  EXPECT_EQ(ev6->dest_ip, "2001:db8::10");
  EXPECT_EQ(ev6->dest_port, 443);

  EtwRecord dns;
  dns.provider = EtwProvider::DnsClient;
  dns.event_id = 3008;
  dns.header_process_id = 900;
  dns.properties = {{"QueryName", std::string("files.example.net")},
                    {"QueryStatus", std::uint64_t{0}},
                    {"QueryResults", std::string("::ffff:192.0.2.80;")}};
  const auto dev = map_etw_record(dns, ctx);
  ASSERT_TRUE(dev.has_value());
  EXPECT_EQ(dev->type, EventType::DnsQuery);
  EXPECT_EQ(dev->pid, 900);
  EXPECT_EQ(dev->query_status, "0");

  EtwRecord other;
  other.provider = EtwProvider::KernelNetwork;
  other.event_id = 10;  // data sent: not mapped
  EXPECT_FALSE(map_etw_record(other, ctx).has_value());
  EtwRecord missing;
  missing.provider = EtwProvider::KernelProcess;
  missing.event_id = 1;  // no ProcessID property
  EXPECT_FALSE(map_etw_record(missing, ctx).has_value());
}

TEST(Etw, Ipv6Formatting) {
  std::vector<std::uint8_t> zeros(16, 0);
  EXPECT_EQ(ipv6_to_string(zeros), "::");
  std::vector<std::uint8_t> loop(16, 0);
  loop[15] = 1;
  EXPECT_EQ(ipv6_to_string(loop), "::1");
  std::vector<std::uint8_t> one_zero = {0, 1, 0, 0, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7};
  EXPECT_EQ(ipv6_to_string(one_zero), "1:0:2:3:4:5:6:7");  // a single zero group is not compressed
  EXPECT_EQ(ipv6_to_string({1, 2}), "");
}

}  // namespace
}  // namespace edr
