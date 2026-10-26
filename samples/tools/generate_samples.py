#!/usr/bin/env python3
"""Regenerate the synthetic samples in samples/ (deterministic; standard library only).

Everything produced here is invented: fictional hosts and users, documentation IP ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), example.com / example.net names, and
harmless command lines. Hashes are SHA-256 digests of the image path string, not of any file.

Usage:  python3 samples/tools/generate_samples.py [--check]
        --check  exit 1 if the files on disk differ from what would be generated (used in CI)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

SAMPLES = Path(__file__).resolve().parent.parent
DOMAIN = "corp.example.com"

# The only encoded payload used anywhere: benign and obviously fake.
DEMO_SCRIPT = "Write-Output 'edr-agent demo: simulated download cradle'"
DEMO_B64 = base64.b64encode(DEMO_SCRIPT.encode("utf-16-le")).decode("ascii")

SYSMON_IDS = {
    "process_create": 1,
    "network_connect": 3,
    "process_terminate": 5,
    "image_load": 7,
    "process_access": 10,
    "file_create": 11,
    "registry_create": 12,
    "registry_delete": 12,
    "registry_set": 13,
    "registry_rename": 14,
    "dns_query": 22,
    "file_delete": 23,
}

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
EXPLORER = r"C:\Windows\explorer.exe"
USERINIT = r"C:\Windows\System32\userinit.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
OUTLOOK = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
SVCHOST = r"C:\Windows\System32\svchost.exe"
SERVICES = r"C:\Windows\System32\services.exe"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest().upper()


def guid(host: str, pid: int) -> str:
    h = hashlib.sha256(f"{host}:{pid}".encode()).hexdigest()
    return "{" + f"5770385f-{h[0:4]}-{h[4:8]}-{h[8:12]}-{h[12:24]}" + "}"


class Scenario:
    """Builds the event list for one host, with Sysmon-style record IDs."""

    def __init__(self, host: str, user: str, start: str, first_record: int) -> None:
        self.host = host
        self.user = user
        self.start = datetime.fromisoformat(start).replace(tzinfo=UTC)
        self.record = first_record
        self.events: list[dict] = []
        self.images: dict[int, str] = {}

    def _base(self, seconds: float, etype: str, pid: int, image: str, source: str) -> dict:
        ts = self.start + timedelta(seconds=seconds)
        self.record += 1
        if source == "sysmon":
            event_id = f"sysmon-{self.host}-{self.record}"
        else:
            event_id = f"etw-{self.host}-{self.record}"
        ev = {
            "id": event_id,
            "ts": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
            "host": self.host,
            "source": source,
            "type": etype,
            "pid": pid,
            "image": image,
        }
        if source == "sysmon":
            ev["sysmon_event_id"] = SYSMON_IDS[etype]
            ev["record_id"] = self.record
            ev["process_guid"] = guid(self.host, pid)
        return ev

    def add(self, ev: dict) -> dict:
        self.events.append(ev)
        return ev

    def proc(self, t: float, pid: int, ppid: int, image: str, cmd: str, *,
             user: str | None = None, integrity: str = "Medium",
             parent_image: str | None = None, parent_cmd: str = "") -> dict:
        ev = self._base(t, "process_create", pid, image, "sysmon")
        parent = parent_image if parent_image is not None else self.images.get(ppid, "")
        ev.update({
            "ppid": ppid,
            "command_line": cmd,
            "user": user or self.user,
            "integrity_level": integrity,
            "hashes": f"SHA256={sha(image)}",
            "parent_process_guid": guid(self.host, ppid),
            "parent_image": parent,
            "parent_command_line": parent_cmd,
        })
        self.images[pid] = image
        return self.add(ev)

    def term(self, t: float, pid: int) -> dict:
        ev = self._base(t, "process_terminate", pid, self.images[pid], "sysmon")
        ev["user"] = self.user
        return self.add(ev)

    def net(self, t: float, pid: int, dest_ip: str, port: int, *, hostname: str = "",
            src_ip: str = "10.20.30.41", src_port: int = 49700) -> dict:
        ev = self._base(t, "network_connect", pid, self.images[pid], "sysmon")
        ev.update({
            "user": self.user,
            "protocol": "tcp",
            "initiated": True,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": port,
            "dest_hostname": hostname,
        })
        return self.add(ev)

    def dns(self, t: float, pid: int, name: str, results: str, *, source: str = "sysmon") -> dict:
        ev = self._base(t, "dns_query", pid, self.images[pid], source)
        ev.update({"user": self.user, "query_name": name, "query_status": "0",
                   "query_results": results})
        return self.add(ev)

    def file(self, t: float, pid: int, path: str, etype: str = "file_create") -> dict:
        ev = self._base(t, etype, pid, self.images[pid], "sysmon")
        ev.update({"user": self.user, "target_path": path})
        return self.add(ev)

    def reg(self, t: float, pid: int, key: str, details: str = "",
            etype: str = "registry_set") -> dict:
        ev = self._base(t, etype, pid, self.images[pid], "sysmon")
        ev.update({"user": self.user, "target_path": key, "details": details,
                   "registry_event_type": {"registry_set": "SetValue",
                                           "registry_create": "CreateKey",
                                           "registry_delete": "DeleteKey"}[etype]})
        return self.add(ev)


def user_sid(n: int) -> str:
    return f"S-1-5-21-1111111111-2222222222-3333333333-{1100 + n}"


def scenario_benign() -> Scenario:
    s = Scenario("SRV-FILES-01", r"CORP\erin.admin", "2026-10-20T08:02:00", 52000)
    s.images[3010] = EXPLORER
    s.proc(0, 3010, 2900, EXPLORER, EXPLORER, parent_image=USERINIT)
    s.proc(15, 3200, 3010, r"C:\Windows\System32\mmc.exe",
           r'"C:\Windows\System32\mmc.exe" "C:\Windows\System32\services.msc"', integrity="High")
    s.proc(70, 3330, 3010, PS, f'"{PS}" -NoProfile', integrity="High")
    s.proc(95, 3340, 3330, r"C:\Windows\System32\Robocopy.exe",
           r'"C:\Windows\System32\Robocopy.exe" D:\Shares\Finance E:\Backup\Finance /MIR /R:1 /W:1',
           integrity="High")
    s.file(160, 3340, r"E:\Backup\Finance\Q3-summary.xlsx")
    s.term(170, 3340)
    s.net(180, 3330, "10.20.5.20", 5985, hostname="srv-mgmt-01.corp.example.com")
    s.proc(300, 3400, 3010, CHROME, f'"{CHROME}"')
    s.dns(301, 3400, "intranet.corp.example.com", "::ffff:10.20.5.40;")
    s.net(302, 3400, "10.20.5.40", 443, hostname="intranet.corp.example.com")
    s.dns(330, 3400, "docs.example.net", "::ffff:198.51.100.21;", source="etw")
    s.net(331, 3400, "198.51.100.21", 443, hostname="docs.example.net")
    s.dns(400, 3400, "www.example.com", "::ffff:198.51.100.20;", source="etw")
    s.net(401, 3400, "198.51.100.20", 443)
    s.proc(900, 3500, 3010, EXCEL,
           f'"{EXCEL}" "E:\\Backup\\Finance\\Q3-summary.xlsx"')
    s.file(1300, 3500, r"C:\Users\erin.admin\Documents\Q3-summary-review.xlsx")
    s.term(1500, 3500)
    s.images[1240] = SVCHOST
    s.proc(1800, 1240, 700, SVCHOST, r"C:\Windows\system32\svchost.exe -k netsvcs -p",
           user=r"NT AUTHORITY\SYSTEM", integrity="System", parent_image=SERVICES)
    s.net(1801, 1240, "198.51.100.30", 443, hostname="update.example.com")
    s.reg(2400, 3330, r"HKLM\SOFTWARE\ExampleCorp\BackupJob\LastRun", "2026-10-20 08:42")
    s.term(2600, 3330)
    s.term(3000, 3400)
    return s


def scenario_phishing() -> Scenario:
    s = Scenario("WS-ALICE-01", r"CORP\alice", "2026-10-20T09:14:00", 1000)
    s.images[3100] = EXPLORER
    s.proc(0, 3100, 2980, EXPLORER, EXPLORER, parent_image=USERINIT)
    s.proc(20, 4000, 3100, OUTLOOK, f'"{OUTLOOK}"')
    s.net(25, 4000, "198.51.100.20", 443, hostname="mail.example.com")
    s.proc(62, 4120, 4000, WINWORD,
           f'"{WINWORD}" /n "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\INetCache'
           f'\\Content.Outlook\\Q7R2KX1M\\Invoice_2291.docm" /o ""')
    s.file(63, 4120, r"C:\Users\alice\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook"
           r"\Q7R2KX1M\~$voice_2291.docm")
    s.proc(70, 5208, 4120, PS,
           f'"{PS}" -NoProfile -WindowStyle Hidden -EncodedCommand {DEMO_B64}')
    s.dns(72, 5208, "update-check.example.net", "::ffff:203.0.113.50;")
    s.net(73, 5208, "203.0.113.50", 8443, src_port=50122)
    s.file(75, 5208, r"C:\Users\alice\AppData\Local\Temp\edr-demo-note.txt")
    s.term(80, 5208)
    s.term(400, 4120)
    return s


def scenario_persistence() -> Scenario:
    s = Scenario("WS-CAROL-03", r"CORP\carol", "2026-10-20T13:30:00", 7700)
    temp_exe = r"C:\Users\carol\AppData\Local\Temp\7zS1A2B\updater_helper.exe"
    sid = user_sid(3)
    s.images[2800] = EXPLORER
    s.proc(0, 2800, 2700, EXPLORER, EXPLORER, parent_image=USERINIT)
    s.proc(30, 6100, 2800, temp_exe, f'"{temp_exe}"')
    s.file(32, 6100, r"C:\Users\carol\AppData\Roaming\ExampleVendor\config.ini")
    s.reg(33, 6100, f"HKU\\{sid}\\Software\\ExampleVendor\\UpdaterHelper\\InstallDir",
          r"C:\Users\carol\AppData\Local\Temp\7zS1A2B")
    s.reg(34, 6100, f"HKU\\{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdaterHelper",
          f'"{temp_exe}" --background')
    s.term(40, 6100)
    return s


def scenario_lolbin() -> Scenario:
    s = Scenario("WS-BOB-02", r"CORP\bob", "2026-10-20T11:05:00", 3300)
    certutil = r"C:\Windows\System32\certutil.exe"
    url = "http://files.example.net/edr-demo/readme.txt"
    out = r"C:\Users\bob\AppData\Local\Temp\readme.txt"
    s.images[2500] = EXPLORER
    s.proc(0, 2500, 2400, EXPLORER, EXPLORER, parent_image=USERINIT)
    s.proc(10, 7000, 2500, CMD, f'"{CMD}" /c certutil.exe -urlcache -split -f {url} {out}')
    s.proc(11, 7012, 7000, certutil, f"certutil.exe  -urlcache -split -f {url} {out}")
    s.dns(12, 7012, "files.example.net", "::ffff:192.0.2.80;")
    s.net(13, 7012, "192.0.2.80", 80, hostname="files.example.net", src_port=50301)
    s.file(14, 7012, out)
    s.term(15, 7012)
    s.term(16, 7000)
    return s


def scenario_noise() -> Scenario:
    s = Scenario("WS-DAVE-04", r"CORP\dave", "2026-10-20T15:00:00", 9100)
    s.images[2600] = EXPLORER
    s.proc(0, 2600, 2500, EXPLORER, EXPLORER, parent_image=USERINIT)
    # A helpdesk technician checks a user's account: four discovery tools in one cmd session.
    s.proc(10, 8000, 2600, CMD, f'"{CMD}"')
    s.proc(20, 8010, 8000, r"C:\Windows\System32\whoami.exe", "whoami /groups")
    s.proc(40, 8020, 8000, r"C:\Windows\System32\net.exe", "net user dave /domain")
    s.proc(41, 8021, 8020, r"C:\Windows\System32\net1.exe", "C:\\Windows\\system32\\net1 user dave /domain")
    s.proc(70, 8030, 8000, r"C:\Windows\System32\systeminfo.exe", "systeminfo")
    s.proc(90, 8040, 8000, r"C:\Windows\System32\nltest.exe", "nltest /dsgetdc:corp.example.com")
    # Browser hitting a CDN that uses random-looking host names.
    s.proc(200, 8100, 2600, CHROME, f'"{CHROME}"')
    for i, label in enumerate(["a8f3kq9z7x2m4v1b", "q2w9e7r4t1y6u3i0", "z5x8c2v7b4n1m6l9",
                               "k3j8h5g2f7d4s1a6"]):
        s.dns(210 + i * 30, 8100, f"{label}.cdn.example.net", "::ffff:198.51.100.60;")
    s.net(215, 8100, "198.51.100.60", 443, hostname="cdn.example.net")
    # A software updater bootstrapper that runs from Temp and also uses random-looking names.
    boot = r"C:\Users\dave\AppData\Local\Temp\{6A1F2C3D-0B4E-4F5A-8C7D-9E0F1A2B3C4D}\setup_bootstrap.exe"
    s.proc(600, 8200, 2600, boot, f'"{boot}" /silent')
    s.dns(605, 8200, "p7r4m1x9c3v6b2n8.updates.example.com", "::ffff:198.51.100.61;")
    s.net(606, 8200, "198.51.100.61", 443)
    s.term(700, 8200)
    # Later, a second, separate discovery check (new cmd window = new tree).
    s.proc(1500, 8300, 2600, CMD, f'"{CMD}"')
    s.proc(1510, 8310, 8300, r"C:\Windows\System32\quser.exe", "quser")
    s.proc(1520, 8320, 8300, r"C:\Windows\System32\whoami.exe", "whoami")
    return s


SCENARIOS = {
    "scenario_1_benign_admin_day": scenario_benign,
    "scenario_2_phishing_chain": scenario_phishing,
    "scenario_3_runkey_persistence": scenario_persistence,
    "scenario_4_lolbin_download": scenario_lolbin,
    "scenario_5_low_severity_noise": scenario_noise,
}

# Pairs the hosts are known to talk to. Only scenario 1 and the noise scenario use them.
BASELINE = {
    "version": 1,
    "pairs": [
        {"host": "SRV-FILES-01", "image": "chrome.exe", "dest": "198.51.100.20"},
        {"host": "SRV-FILES-01", "image": "chrome.exe", "dest": "198.51.100.21"},
        {"host": "SRV-FILES-01", "image": "svchost.exe", "dest": "198.51.100.30"},
        {"host": "WS-ALICE-01", "image": "outlook.exe", "dest": "198.51.100.20"},
        {"host": "WS-DAVE-04", "image": "chrome.exe", "dest": "198.51.100.60"},
        {"host": "WS-DAVE-04", "image": "setup_bootstrap.exe", "dest": "198.51.100.61"},
    ],
}


# ---------------------------------------------------------------------------------------------
# Sysmon XML rendering (what EvtRender with EvtRenderEventXml returns, minus real values)
# ---------------------------------------------------------------------------------------------

def _sysmon_utc(ts: str) -> str:
    # "2026-10-20T09:15:02.123Z" -> "2026-10-20 09:15:02.123"
    return ts.replace("T", " ").rstrip("Z")


def _data_fields(ev: dict) -> list[tuple[str, str]]:
    utc = _sysmon_utc(ev["ts"])
    t = ev["type"]
    common = [("RuleName", "-"), ("UtcTime", utc)]
    pg = ("ProcessGuid", ev.get("process_guid", ""))
    pid = ("ProcessId", str(ev["pid"]))
    img = ("Image", ev["image"])
    user = ("User", ev.get("user", ""))
    if t == "process_create":
        return common + [pg, pid, img,
                         ("FileVersion", "-"), ("Description", "-"), ("Product", "-"),
                         ("Company", "-"), ("OriginalFileName", "-"),
                         ("CommandLine", ev["command_line"]),
                         ("CurrentDirectory", "C:\\Windows\\system32\\"), user,
                         ("LogonGuid", "{5770385f-0000-0000-0000-000000000000}"),
                         ("LogonId", "0x3e7"), ("TerminalSessionId", "1"),
                         ("IntegrityLevel", ev["integrity_level"]), ("Hashes", ev["hashes"]),
                         ("ParentProcessGuid", ev["parent_process_guid"]),
                         ("ParentProcessId", str(ev["ppid"])),
                         ("ParentImage", ev["parent_image"]),
                         ("ParentCommandLine", ev["parent_command_line"]),
                         ("ParentUser", ev.get("user", ""))]
    if t == "process_terminate":
        return common + [pg, pid, img, user]
    if t == "network_connect":
        return common + [pg, pid, img, user, ("Protocol", ev["protocol"]),
                         ("Initiated", "true" if ev["initiated"] else "false"),
                         ("SourceIsIpv6", "false"), ("SourceIp", ev["src_ip"]),
                         ("SourceHostname", "-"), ("SourcePort", str(ev["src_port"])),
                         ("SourcePortName", "-"), ("DestinationIsIpv6", "false"),
                         ("DestinationIp", ev["dest_ip"]),
                         ("DestinationHostname", ev["dest_hostname"] or "-"),
                         ("DestinationPort", str(ev["dest_port"])),
                         ("DestinationPortName", "-")]
    if t == "dns_query":
        return common + [pg, pid, ("QueryName", ev["query_name"]),
                         ("QueryStatus", ev["query_status"]),
                         ("QueryResults", ev["query_results"]), img, user]
    if t in ("file_create", "file_delete"):
        return common + [pg, pid, img, ("TargetFilename", ev["target_path"]),
                         ("CreationUtcTime", utc), user]
    if t.startswith("registry_"):
        fields = common[:1] + [("EventType", ev["registry_event_type"])] + common[1:] + [
            pg, pid, img, ("TargetObject", ev["target_path"])]
        if t == "registry_set":
            fields.append(("Details", ev["details"]))
        fields.append(user)
        return fields
    raise ValueError(f"no Sysmon rendering for {t}")


def render_sysmon_xml(ev: dict) -> str:
    computer = f"{ev['host']}.{DOMAIN}"
    data = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in _data_fields(ev))
    system_time = ev["ts"].replace("Z", "0000Z")
    task = {1: 1, 3: 3, 5: 5, 11: 11, 12: 12, 13: 13, 14: 14, 22: 22, 23: 23}[ev["sysmon_event_id"]]
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Microsoft-Windows-Sysmon" '
        'Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>'
        f"<EventID>{ev['sysmon_event_id']}</EventID><Version>5</Version><Level>4</Level>"
        f"<Task>{task}</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>"
        f'<TimeCreated SystemTime="{system_time}"/>'
        f"<EventRecordID>{ev['record_id']}</EventRecordID><Correlation/>"
        '<Execution ProcessID="2956" ThreadID="3780"/>'
        "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        f"<Computer>{computer}</Computer>"
        '<Security UserID="S-1-5-18"/></System>'
        f"<EventData>{data}</EventData></Event>"
    )


# ---------------------------------------------------------------------------------------------
# Per-rule positive and negative cases (shared by the C++ and Python rule tests)
# ---------------------------------------------------------------------------------------------

def _ev(etype: str, **fields: object) -> dict:
    base = {"id": "case", "ts": "2026-10-20T10:00:00.000Z", "host": "WS-TEST-01",
            "source": "replay", "type": etype, "pid": 100, "image": r"C:\Windows\System32\x.exe"}
    base.update(fields)
    return base


def rule_cases() -> list[dict]:
    tmp = r"C:\Users\frank\AppData\Local\Temp"
    run = r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run\Demo"
    cases = [
        ("encoded-powershell", True, "powershell -enc with a valid payload",
         _ev("process_create", image=PS, command_line=f"powershell.exe -enc {DEMO_B64}")),
        ("encoded-powershell", True, "pwsh with /EncodedCommand and quotes",
         _ev("process_create", image=r"C:\Program Files\PowerShell\7\pwsh.exe",
             command_line=f'pwsh.exe /EncodedCommand "{DEMO_B64}"')),
        ("encoded-powershell", False, "flag present but payload is not Base64",
         _ev("process_create", image=PS, command_line="powershell.exe -enc not*base64!")),
        ("encoded-powershell", False, "plain PowerShell command",
         _ev("process_create", image=PS, command_line="powershell.exe -NoProfile Get-Date")),
        ("encoded-powershell", False, "-ExecutionPolicy is not an encoded-command prefix",
         _ev("process_create", image=PS,
             command_line="powershell.exe -ExecutionPolicy Bypass -File a.ps1")),
        ("office-spawns-script-host", True, "Word starts PowerShell",
         _ev("process_create", image=PS, parent_image=WINWORD, command_line="powershell")),
        ("office-spawns-script-host", True, "Excel starts cmd",
         _ev("process_create", image=CMD, parent_image=EXCEL, command_line="cmd /c echo")),
        ("office-spawns-script-host", False, "Explorer starts PowerShell",
         _ev("process_create", image=PS, parent_image=EXPLORER, command_line="powershell")),
        ("office-spawns-script-host", False, "Word starts a non-script child",
         _ev("process_create", image=r"C:\Windows\splwow64.exe", parent_image=WINWORD)),
        ("lolbin-network", True, "certutil to a public address",
         _ev("network_connect", image=r"C:\Windows\System32\certutil.exe",
             dest_ip="198.51.100.9", dest_port=443)),
        ("lolbin-network", True, "mshta to IPv6 documentation range (not private)",
         _ev("network_connect", image=r"C:\Windows\System32\mshta.exe",
             dest_ip="2001:db8::10", dest_port=80)),
        ("lolbin-network", False, "certutil to an internal proxy",
         _ev("network_connect", image=r"C:\Windows\System32\certutil.exe",
             dest_ip="10.1.2.3", dest_port=8080)),
        ("lolbin-network", False, "browser to a public address",
         _ev("network_connect", image=CHROME, dest_ip="198.51.100.9", dest_port=443)),
        ("run-key-persistence", True, "HKCU-style Run value",
         _ev("registry_set", target_path=run, details="C:\\x.exe")),
        ("run-key-persistence", True, "HKLM WOW6432Node RunOnce value",
         _ev("registry_set", target_path=r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows"
                                         r"\CurrentVersion\RunOnce\Setup", details="x")),
        ("run-key-persistence", False, "RunMRU is not a Run key",
         _ev("registry_set", target_path=r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows"
                                         r"\CurrentVersion\Explorer\RunMRU\a", details="x")),
        ("service-created-via-registry", True, "new service ImagePath",
         _ev("registry_set", image=SERVICES,
             target_path=r"HKLM\System\CurrentControlSet\Services\DemoSvc\ImagePath",
             details=r"C:\ProgramData\demo\svc.exe")),
        ("service-created-via-registry", False, "Windows Installer servicing",
         _ev("registry_set", image=r"C:\Windows\System32\msiexec.exe",
             target_path=r"HKLM\System\CurrentControlSet\Services\DemoSvc\ImagePath")),
        ("service-created-via-registry", False, "other service value",
         _ev("registry_set", image=SERVICES,
             target_path=r"HKLM\System\CurrentControlSet\Services\DemoSvc\Start", details="2")),
        ("lsass-access", True, "unknown tool reads LSASS memory",
         _ev("process_access", image=r"C:\Users\frank\Downloads\tool.exe",
             target_image=r"C:\Windows\system32\lsass.exe", granted_access="0x1010")),
        ("lsass-access", False, "Defender scanning LSASS",
         _ev("process_access", image=r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe",
             target_image=r"C:\Windows\system32\lsass.exe", granted_access="0x1410")),
        ("lsass-access", False, "query-only access right",
         _ev("process_access", image=r"C:\Users\frank\Downloads\tool.exe",
             target_image=r"C:\Windows\system32\lsass.exe", granted_access="0x1000")),
        ("startup-folder-drop", True, "shortcut in the user's Startup folder",
         _ev("file_create", target_path=r"C:\Users\frank\AppData\Roaming\Microsoft\Windows"
                                        r"\Start Menu\Programs\Startup\demo.lnk")),
        ("startup-folder-drop", False, "file in the Start Menu but not Startup",
         _ev("file_create", target_path=r"C:\ProgramData\Microsoft\Windows\Start Menu"
                                        r"\Programs\Demo\demo.lnk")),
        ("dns-high-entropy", True, "long random label",
         _ev("dns_query", query_name="a8f3kq9z7x2m4v1b.example.net")),
        ("dns-high-entropy", False, "ordinary long label",
         _ev("dns_query", query_name="update-check.example.net")),
        ("dns-high-entropy", False, "short random label",
         _ev("dns_query", query_name="x7k2q.example.net")),
        ("script-host-nonstandard-port", True, "PowerShell to a public address on 8443",
         _ev("network_connect", image=PS, dest_ip="203.0.113.50", dest_port=8443)),
        ("script-host-nonstandard-port", False, "PowerShell to a public address on 443",
         _ev("network_connect", image=PS, dest_ip="203.0.113.50", dest_port=443)),
        ("script-host-nonstandard-port", False, "PowerShell remoting inside the LAN",
         _ev("network_connect", image=PS, dest_ip="10.20.5.20", dest_port=4444)),
        ("exec-from-user-temp", True, "program in AppData Local Temp",
         _ev("process_create", image=tmp + r"\demo.exe")),
        ("exec-from-user-temp", True, "upper-case drive and path",
         _ev("process_create", image=r"D:\USERS\FRANK\APPDATA\LOCAL\TEMP\X\demo.exe")),
        ("exec-from-user-temp", False, "program in Downloads",
         _ev("process_create", image=r"C:\Users\frank\Downloads\demo.exe")),
        ("shadow-copy-deletion", True, "vssadmin delete shadows",
         _ev("process_create", image=r"C:\Windows\System32\vssadmin.exe",
             command_line="vssadmin.exe Delete Shadows /All /Quiet")),
        ("shadow-copy-deletion", True, "wmic shadowcopy delete",
         _ev("process_create", image=r"C:\Windows\System32\wbem\WMIC.exe",
             command_line="wmic shadowcopy delete")),
        ("shadow-copy-deletion", False, "vssadmin list shadows",
         _ev("process_create", image=r"C:\Windows\System32\vssadmin.exe",
             command_line="vssadmin list shadows")),
        ("discovery-commands", True, "whoami",
         _ev("process_create", image=r"C:\Windows\System32\whoami.exe", command_line="whoami")),
        ("discovery-commands", False, "hostname is not in the list",
         _ev("process_create", image=r"C:\Windows\System32\HOSTNAME.EXE")),
        ("scheduled-task-created", True, "schtasks /create",
         _ev("process_create", image=r"C:\Windows\System32\schtasks.exe",
             command_line="schtasks /Create /SC DAILY /TN Demo /TR C:\\demo.exe")),
        ("scheduled-task-created", False, "schtasks /query",
         _ev("process_create", image=r"C:\Windows\System32\schtasks.exe",
             command_line="schtasks /query")),
        ("scheduled-task-created", False, "right image, wrong event type",
         _ev("network_connect", image=r"C:\Windows\System32\schtasks.exe",
             command_line="schtasks /create", dest_ip="198.51.100.1", dest_port=443)),
    ]
    return [{"rule": r, "expect": e, "name": n, "event": ev} for r, e, n, ev in cases]


def build() -> dict[Path, str]:
    out: dict[Path, str] = {}
    for name, factory in SCENARIOS.items():
        scen = factory()
        lines = [json.dumps(ev, sort_keys=False, ensure_ascii=False) for ev in scen.events]
        out[SAMPLES / f"{name}.jsonl"] = "\n".join(lines) + "\n"
        xml_events = [render_sysmon_xml(ev) for ev in scen.events if ev["source"] == "sysmon"]
        out[SAMPLES / "sysmon_xml" / f"{name}.xml"] = (
            "<Events>\n" + "\n".join(xml_events) + "\n</Events>\n")
    out[SAMPLES / "baseline.json"] = json.dumps(BASELINE, indent=2) + "\n"
    out[SAMPLES / "rule_cases.jsonl"] = "\n".join(
        json.dumps(c, ensure_ascii=False) for c in rule_cases()) + "\n"
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if samples are out of date")
    args = parser.parse_args()
    files = build()
    stale = [p for p, text in files.items() if not p.exists() or p.read_text("utf-8") != text]
    if args.check:
        for p in stale:
            print(f"out of date: {p.relative_to(SAMPLES.parent)}", file=sys.stderr)
        return 1 if stale else 0
    for p, text in files.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, "utf-8", newline="\n")
    print(f"wrote {len(files)} files ({len(stale)} changed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
