# -*- coding: utf-8 -*-
"""LanSeek —— LAN Device Scanner (网寻 —— 局域网设备扫描器)。

原理：
    1) 用 UDP 选路拿到当前活跃网卡的 IPv4，再到 netsh 里找出它的接口名和本机地址，
       默认扫描网段取该地址所在 /24（最后一段 0-255）；
    2) Windows 下直调 ICMP API 并发探测，一次 GetIpNetTable 读 ARP 表取 MAC；
    3) 网卡名后面括号里显示当前连接的网络名：无线取 SSID（netsh wlan），
       有线取 Windows 网络配置名（Get-NetConnectionProfile，后台线程取，不拖慢启动）；
    4) 备注列只标出本机地址所在的那一行。

用法：
    python lanseek.py                            # 图形界面（默认英文，菜单可切换中文）
    python lanseek.py 192.168.0.1 192.168.0.254  # 命令行扫描，只打印在线主机
"""
import ctypes
import ipaddress
import locale
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from array import array
from concurrent.futures import ThreadPoolExecutor, as_completed

WINDOWS = sys.platform == "win32"
_NO_WINDOW = 0x08000000 if WINDOWS else 0   # 隐藏 ping/arp/netsh 的控制台黑框
MAX_HOSTS = 4096                            # 单次扫描地址数上限
WORKERS = 128                               # 并发探测线程数（Windows 直调 API，子进程模式下也有效）
DEFAULT_TIMEOUT = 500                       # 默认超时 ms（慢速设备请自行调大）
REG_PATH = r"Software\LanSeek"              # 语言记在注册表里，不落任何文件
RELEASE_URL = "https://github.com/cnybh/LanSeek"    # “关于”里的软件发布页
# ping/arp 的取值都是 ASCII，按字节正则解析，绕开中文/英文系统的编码差异
TTL_RE = re.compile(rb"TTL=(\d+)", re.I)
RTT_RE = re.compile(rb"[=<]\s*(\d+)\s*ms", re.I)
ARP_RE = re.compile(rb"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})", re.I)
# netsh 输出先解码再解析，只认取值的形状，不匹配会被翻译的文字标签
IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
QUOTED_RE = re.compile(r'"([^"]+)"')        # netsh 里接口名总带引号，不受系统语言影响
SSID_RE = re.compile(r"^\s*SSID\s*:\s*(\S.*?)\s*$")     # BSSID 开头不同，不会误匹配
SECTION_RE = re.compile(rb"^\s*\S*\s*(\d{1,3}(?:\.\d{1,3}){3})\s*---\s*0x", re.I)  # arp -a 的接口分节头


def _run(args):
    """执行外部命令并返回原始字节输出。"""
    try:
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              creationflags=_NO_WINDOW).stdout
    except OSError:
        return b""


def _decode(raw):
    """按系统代码页解码 netsh 输出（SSID、接口名可能含中文）。"""
    try:
        return raw.decode(locale.getpreferredencoding(False) or "ascii", "replace")
    except LookupError:
        return raw.decode("ascii", "replace")


def _ip_to_int(ip):
    """IPv4 文本或整数 -> 主机序整数，扫描内部统一用整数表示地址。"""
    return ip if isinstance(ip, int) else int(ipaddress.IPv4Address(ip.strip()))


def _ip_text(ip_int):
    """主机序 IPv4 整数 -> 点分文本，只在显示/打印时转换。"""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


_WINAPI = None
_WINAPI_LOCK = threading.Lock()


def _win_api():
    """Windows iphlpapi.dll 的 ctypes 封装，首次调用时初始化。"""
    global _WINAPI
    if _WINAPI is not None:
        return _WINAPI
    with _WINAPI_LOCK:
        if _WINAPI is not None:
            return _WINAPI

        class IP_OPTION_INFORMATION(ctypes.Structure):
            _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                        ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                        ("OptionsData", ctypes.c_void_p)]

        class ICMP_ECHO_REPLY(ctypes.Structure):
            _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong),
                        ("RoundTripTime", ctypes.c_ulong), ("DataSize", ctypes.c_ushort),
                        ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                        ("Options", IP_OPTION_INFORMATION)]

        dll = ctypes.WinDLL("iphlpapi.dll")
        create = dll.IcmpCreateFile
        create.restype = ctypes.c_void_p
        close = dll.IcmpCloseHandle
        close.argtypes = [ctypes.c_void_p]
        close.restype = ctypes.c_ulong
        send1 = dll.IcmpSendEcho
        send1.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                          ctypes.c_ushort, ctypes.POINTER(IP_OPTION_INFORMATION),
                          ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
        send1.restype = ctypes.c_ulong
        try:
            send2 = dll.IcmpSendEcho2Ex
            send2.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                              ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                              ctypes.c_void_p, ctypes.c_ushort,
                              ctypes.POINTER(IP_OPTION_INFORMATION),
                              ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
            send2.restype = ctypes.c_ulong
        except AttributeError:
            send2 = None
        sendarp = dll.SendARP
        sendarp.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_ulong)]
        sendarp.restype = ctypes.c_ulong
        gettable = dll.GetIpNetTable
        gettable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong),
                             ctypes.c_bool]
        gettable.restype = ctypes.c_ulong
        _WINAPI = {"dll": dll, "create": create, "close": close,
                   "send1": send1, "send2": send2, "sendarp": sendarp,
                   "gettable": gettable, "reply": ICMP_ECHO_REPLY}
        return _WINAPI


class _IcmpWorker:
    """每个探测线程持有一个 ICMP 句柄和回复缓冲区，循环探测时复用。"""

    def __init__(self, source_int):
        api = _win_api()
        self._api = api
        self._handle = api["create"]()
        self._send2 = api["send2"]
        self._send1 = api["send1"]
        self._src = ctypes.c_ulong(socket.htonl(source_int)) if source_int else ctypes.c_ulong(0)
        reply = api["reply"]
        self._buf = ctypes.create_string_buffer(ctypes.sizeof(reply) + 32 + 8)
        self._data = ctypes.create_string_buffer(32)
        self._reply = ctypes.cast(self._buf, ctypes.POINTER(reply))

    def probe(self, ip_int, timeout_ms):
        if self._handle in (None, 0, ctypes.c_void_p(-1).value):
            return None
        dst = ctypes.c_ulong(socket.htonl(ip_int))
        if self._send2 is not None:
            n = self._send2(self._handle, None, None, None, self._src, dst,
                            self._data, 32, None, self._buf, len(self._buf),
                            timeout_ms)
        else:
            n = self._send1(self._handle, dst, self._data, 32, None,
                            self._buf, len(self._buf), timeout_ms)
        if n:
            reply = self._reply.contents
            if reply.Status == 0:
                return reply.RoundTripTime, reply.Options.Ttl
        return None

    def close(self):
        if self._handle not in (None, 0, ctypes.c_void_p(-1).value):
            self._api["close"](self._handle)
            self._handle = None


def _mac_via_sendarp(ip_int, source_int):
    """SendARP 取单个地址 MAC；失败返回空字符串。"""
    api = _win_api()
    dst = ctypes.c_ulong(socket.htonl(ip_int))
    src = ctypes.c_ulong(socket.htonl(source_int)) if source_int else ctypes.c_ulong(0)
    mac = (ctypes.c_ubyte * 6)()
    length = ctypes.c_ulong(6)
    if api["sendarp"](dst, src, ctypes.byref(mac), ctypes.byref(length)) == 0 and length.value == 6:
        return "-".join("%02X" % byte for byte in mac)
    return ""


def _mac_table_windows():
    """GetIpNetTable 一次读取系统 ARP 表 -> {ip(int): MAC}。"""
    api = _win_api()

    class MIB_IPNETROW(ctypes.Structure):
        _fields_ = [("dwIndex", ctypes.c_ulong), ("dwPhysAddrLen", ctypes.c_ulong),
                    ("bPhysAddr", ctypes.c_ubyte * 8),
                    ("dwAddr", ctypes.c_ulong), ("dwType", ctypes.c_ulong)]

    size = ctypes.c_ulong(0)
    ret = api["gettable"](None, ctypes.byref(size), False)
    if ret not in (0, 122):                     # 122 = ERROR_INSUFFICIENT_BUFFER
        return {}
    if size.value == 0:
        return {}
    buf = ctypes.create_string_buffer(size.value)
    ret = api["gettable"](buf, ctypes.byref(size), False)
    if ret != 0:
        return {}
    row_size = ctypes.sizeof(MIB_IPNETROW)
    table = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong)).contents.value
    macs = {}
    for i in range(table):
        row = MIB_IPNETROW()
        ctypes.memmove(ctypes.byref(row),
                       ctypes.addressof(buf) + 4 + i * row_size, row_size)
        if row.dwPhysAddrLen != 6 or not any(row.bPhysAddr):
            continue
        host_ip = socket.ntohl(row.dwAddr)
        if host_ip == 0 or host_ip in macs:
            continue
        macs[host_ip] = "-".join("%02X" % row.bPhysAddr[j] for j in range(6))
    return macs


def _source_ok(source, timeout_ms):
    """验证 source 能作为绑定源地址；Windows 用 API，其他平台保留 ping 兜底。"""
    if not source:
        return False
    if WINDOWS:
        try:
            ip = _ip_to_int(source)
            worker = _IcmpWorker(ip)
            try:
                return worker.probe(ip, timeout_ms) is not None
            finally:
                worker.close()
        except OSError:
            pass
    return ping(source, timeout_ms, source) is not None


def ping(ip, timeout_ms=DEFAULT_TIMEOUT, source=""):
    """ping 一个地址。通 -> (延时 ms, TTL)；不通 -> None。
    source 非空时用 -S 绑定源地址，强制从指定的那块网卡出去。"""
    if WINDOWS:
        args = ["ping"] + (["-S", source] if source else []) \
            + ["-n", "1", "-w", str(timeout_ms), ip]
    else:
        args = ["ping"] + (["-I", source] if source else []) \
            + ["-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    out = _run(args)
    ttl, rtt = TTL_RE.search(out), RTT_RE.search(out)
    if not (ttl and rtt):       # 超时、不可达：没有 TTL 或没有时间字段
        return None
    return int(rtt.group(1)), int(ttl.group(1))


def arp_table(interface_ip=""):
    """读取系统 ARP 缓存 -> {ip: MAC}，MAC 统一成大写、以 - 分隔（同 ipconfig 的写法）。
    指定接口地址时只取该接口那一段（多网卡才分得清）。"""
    sections, current = {}, None
    for line in _run(["arp", "-a"]).splitlines():
        header = SECTION_RE.match(line)
        if header:
            current = header.group(1).decode()
            sections.setdefault(current, {})
            continue
        if current is None:
            continue
        for ip, mac in ARP_RE.findall(line):
            sections[current][ip.decode()] = mac.decode().replace(":", "-").upper()
    if interface_ip in sections:
        return sections[interface_ip]
    return {ip: mac for table in sections.values() for ip, mac in table.items()}


def _blocks(text):
    """把 netsh 输出按空行切块 -> [(块内全文, [每行冒号后的取值])]。"""
    result, current = [], []
    for line in text.splitlines():
        if line.strip():
            current.append(line)
        elif current:
            result.append(current)
            current = []
    if current:
        result.append(current)
    return [("\n".join(lines), [line.split(":", 1)[1].strip() for line in lines if ":" in line])
            for lines in result]


def _ipv4_blocks():
    """netsh interface ipv4 show addresses -> [(接口名, 接口地址, 该块取值)]。"""
    blocks = []
    for text, values in _blocks(_decode(_run(["netsh", "interface", "ipv4", "show", "addresses"]))):
        names = QUOTED_RE.findall(text)
        if not names:
            continue
        # 第一个“像地址”的取值就是接口地址（掩码必然以 255. 开头，子网前缀带 / 号）
        address = next((v for v in values if IPV4_RE.fullmatch(v) and not v.startswith("255.")), "")
        blocks.append((names[0], address, values))
    return blocks


def local_addresses():
    """本机所有 IPv4（含回环、虚拟网卡），用来标出“本机”那一行。"""
    return {address for _, address, _ in _ipv4_blocks() if address}


def preferred_ip():
    """系统首选源地址（UDP 选路，不发包）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))       # 只让系统按路由表挑源地址
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


def adapter_names():
    """本机真实网卡名（netsh interface show interface）。该命令不含环回伪接口
    和 Wi-Fi Direct 虚拟适配器，正是要列给用户的那几块；第一行是表头，跳过。"""
    names = []
    lines = [line for line in _decode(_run(["netsh", "interface", "show", "interface"])
                                     ).splitlines() if line.strip()]
    for line in lines[1:]:                       # 第一行是表头；第二行是分隔线，token 太少会被跳过
        parts = line.split()                     # Admin State / State / Type / 名称（名称可能带空格）
        if len(parts) > 3:
            name = " ".join(parts[3:])
            if name and name not in names:
                names.append(name)
    return names


def adapters():
    """本机网卡清单 -> [(名称, IPv4 或 "")]，有默认网关的排前面。
    未插网线的网卡也在列（地址为空），由界面标成“未连接”。
    两个 netsh 命令用线程并行执行，节省一半启动等待时间。"""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_ipv4_blocks)
        f2 = pool.submit(adapter_names)
        blocks = f1.result()
        names = f2.result()
    known = {name: (address, values) for name, address, values in blocks}
    items = []
    for index, name in enumerate(names):
        address, values = known.get(name, ("", []))
        gateway = any(IPV4_RE.fullmatch(v) and v != address and not v.startswith("255.")
                      for v in values)
        items.append((not gateway, index, name, address))
    items.sort()
    return [(name, address) for _, _, name, address in items]


def range_for(ip):
    """某个本机地址所在 /24，最后一段 0-255。"""
    base = ip.rsplit(".", 1)[0] if ip.count(".") == 3 else "192.168.0"
    return base + ".0", base + ".255"


def network_name(adapter_name):
    """当前连接的网络名：无线取 SSID，有线取 Windows 网络配置名。取不到返回 ""。"""
    for text, values in _blocks(_decode(_run(["netsh", "wlan", "show", "interfaces"]))):
        if adapter_name not in values:
            continue
        for line in text.splitlines():
            found = SSID_RE.match(line)
            if found:
                return found.group(1)
    # 有线网卡（或无线取不到 SSID）：问系统当前的网络配置名，冷启动可能要几秒
    script = ("Get-NetConnectionProfile | Where-Object {$_.InterfaceAlias -eq '%s'}"
              " | Select-Object -First 1 -ExpandProperty Name" % adapter_name.replace("'", "''"))
    return _decode(_run(["powershell", "-NoProfile", "-Command", script])).strip()


def open_adapter_properties(adapter_name):
    """打开某块网卡的“属性”页 —— IPv4 配置就在这一页里。

    走 Shell.Application：在“网络连接”文件夹里按名字找到该网卡，执行它的“属性”动词。
    属性窗口归发起调用的 powershell 进程所有，所以脚本要活到窗口关掉为止，
    否则窗口会跟着进程一起消失。动词名各语言不同（P&roperties / 属性(&P)），
    统一去掉 & 之后再匹配；名字对不上或没有该动词就退回网络连接列表。
    """
    if not WINDOWS or not adapter_name:
        return
    script = ("$n='" + adapter_name.replace("'", "''") + "';"
              "$f=(New-Object -ComObject Shell.Application)"
              ".NameSpace('::{7007ACC7-3202-11D1-AAD2-00805FC1270E}');"
              "$a=$f.Items()|Where-Object{$_.Name -eq $n}|Select-Object -First 1;"
              "$v=if($a){$a.Verbs()|Where-Object{($_.Name -replace '&','')"
              " -match '^(Properties|属性)'}|Select-Object -First 1};"
              "if($v){$v.DoIt();"
              "for($i=0;$i -lt 40;$i++){Start-Sleep -Milliseconds 250;"
              "if((Get-Process -Id $PID).MainWindowTitle){break}};"
              "while((Get-Process -Id $PID).MainWindowTitle){Start-Sleep -Milliseconds 500}}"
              "else{Start-Process ncpa.cpl}")
    try:
        subprocess.Popen(["powershell", "-NoProfile", "-Command", script],
                         creationflags=_NO_WINDOW)
    except OSError:
        pass


def load_lang():
    """从注册表读上次选择的语言；没有记录或读不到就按英文。"""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH) as key:
            value = winreg.QueryValueEx(key, "Language")[0]
        return value if value in TEXT else "en"
    except (OSError, ImportError):
        return "en"


def save_lang(lang):
    """把语言写进注册表（不落任何文件）。"""
    try:
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH) as key:
            winreg.SetValueEx(key, "Language", 0, winreg.REG_SZ, lang)
    except (OSError, ImportError):
        pass


def parse_range(first, last):
    """起始/结束 IP -> 紧凑 IPv4 整数数组。非法输入抛 ValueError。"""
    start, end = ipaddress.IPv4Address(first.strip()), ipaddress.IPv4Address(last.strip())
    count = int(end) - int(start) + 1
    if count < 1:
        raise ValueError("end < start")
    if count > MAX_HOSTS:
        raise ValueError("too many: %d > %d" % (count, MAX_HOSTS))
    return array("I", (int(start) + i for i in range(count)))


def _scan_subprocess(hosts, timeout_ms, workers, on_row, source):
    """非 Windows 兜底：保留 ping 子进程 + arp 缓存取 MAC。"""
    text_hosts = [_ip_text(ip) for ip in hosts]
    macs = arp_table(source)
    local = local_addresses()
    index_of = {ip: i for i, ip in enumerate(text_hosts)}

    def finish(ip, hit):
        return (ip, macs.get(ip, ""), str(hit[1]) if hit else "", str(hit[0]) if hit else "",
                bool(hit), ip in local)

    hits = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(ping, ip, timeout_ms, source): ip for ip in text_hosts}
        for future in as_completed(futures):
            ip = futures[future]
            hits[ip] = future.result()
            if on_row:
                on_row(index_of[ip], finish(ip, hits[ip]))
    macs = arp_table(source)                # 扫完再读：这次能看到本次 ping 新学到的 MAC
    return [finish(ip, hits[ip]) for ip in text_hosts]


def _scan_windows(hosts, timeout_ms, workers, on_row, source, collect):
    """Windows 直调 ICMP 并发探测，扫描后一次 GetIpNetTable 读 MAC。

    先按探测完成顺序交初步行（MAC 留空），ARP 表到位后再按原始顺序交最终行，
    界面既能边扫边显示，又能拿到最新的 MAC。
    """
    total = len(hosts)
    local = {_ip_to_int(address) for address in local_addresses()}
    source_int = _ip_to_int(source) if source else 0
    next_index = 0
    lock = threading.Lock()
    callback_lock = threading.Lock()
    hits = [None] * total

    def row_text(index, hit, mac):
        return (_ip_text(hosts[index]), mac,
                str(hit[1]) if hit else "", str(hit[0]) if hit else "",
                bool(hit), hosts[index] in local)

    def worker():
        nonlocal next_index
        probe = _IcmpWorker(source_int)
        try:
            while True:
                with lock:
                    if next_index >= total:
                        return
                    index = next_index
                    next_index += 1
                hit = probe.probe(hosts[index], timeout_ms)
                hits[index] = hit
                if on_row and hit:
                    row = row_text(index, hit, "")
                    with callback_lock:
                        on_row(index, row)
        finally:
            probe.close()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(workers, total) if total else 0)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    macs = _mac_table_windows()
    missing = [i for i in range(total) if hits[i] and hosts[i] not in macs]
    if missing:
        for i in missing:
            mac = _mac_via_sendarp(hosts[i], source_int)
            if mac:
                macs[hosts[i]] = mac

    rows = [None] * total if collect else None
    for index in range(total):
        hit = hits[index]
        row = row_text(index, hit, macs.get(hosts[index], ""))
        if on_row:
            on_row(index, row)
        if collect:
            rows[index] = row
    return rows


def scan(hosts, timeout_ms=DEFAULT_TIMEOUT, workers=WORKERS, on_row=None, source="",
         collect=True):
    """并发探测 hosts，返回 [(ip, mac, ttl, delay, 在线, 是否本机)]，顺序同 hosts。

    每探完一个地址立刻用 on_row(index, row) 回调交出一行，界面据此边扫边显示。
    source 是所选网卡的地址，Windows 下 ICMP/SendARP 都绑它；
    collect=False 时用于 GUI 实时填充，不再额外构建整份返回列表。
    """
    if WINDOWS:
        try:
            _win_api()
            return _scan_windows(hosts, timeout_ms, workers, on_row, source, collect)
        except OSError:
            return _scan_subprocess(hosts, timeout_ms, workers, on_row, source)
    return _scan_subprocess(hosts, timeout_ms, workers, on_row, source)


TEXT = {
    "en": {
        "title": "LanSeek - LAN Device Scanner",
        "adapter_label": "Adapter:",
        "show_offline": "Show offline", "scan": "Scan", "clear": "Clear", "configure": "Configure",
        "col_ip": "IP", "col_mac": "MAC Address", "col_ttl": "TTL", "col_delay": "Delay (ms)",
        "col_state": "State", "col_note": "Note", "local": "This PC",
        "online": "Online", "offline": "Offline",
        "menu_program": "Program (P)", "menu_about": "About", "menu_exit": "Exit",
        "menu_language": "Language (L)", "menu_switch": "Switch to 中文",
        "about": "LanSeek - LAN Device Scanner\nby Yangbohang", "disconnected": "Disconnected",
        "release_page": "Software Release Page",
        "bad_input": "Invalid input", "scan_failed": "Scan failed",
        "status_scanning": "Scanning %d/%d",
        "status_ready": "Ready, %d online",
        "status_idle": "Not scanned yet",
        "status_cleared": "Cleared",
        "status_error": "Error: %s",
        "no_source": "Source not bound",
        "ip_label": "IP", "timeout_label": "Timeout (ms)",
    },
    "zh": {
        "title": "LanSeek 网寻 - 局域网设备扫描器",
        "adapter_label": "网络适配器：",
        "show_offline": "显示离线", "scan": "扫描", "clear": "清空", "configure": "配置",
        "col_ip": "IP", "col_mac": "MAC 地址", "col_ttl": "TTL", "col_delay": "延时(ms)",
        "col_state": "状态", "col_note": "备注", "local": "本机",
        "online": "在线", "offline": "离线",
        "menu_program": "程序(P)", "menu_about": "关于", "menu_exit": "退出",
        "menu_language": "语言(L)", "menu_switch": "切换至English",
        "about": "网寻-局域网设备扫描器\nby Yangbohang",
        "release_page": "软件发布页",
        "status_scanning": "搜索中 第%d/共%d",
        "status_ready": "就绪，共 %d 台设备在线",
        "status_idle": "未执行扫描",
        "status_cleared": "已清空",
        "status_error": "错误：%s",
        "disconnected": "未连接",
        "bad_input": "输入有误", "scan_failed": "扫描失败",
        "no_source": "源未绑定",
        "ip_label": "IP", "timeout_label": "超时(ms)",
    },
}


# 列宽用比例表示：IP/MAC/TTL/延时/状态/备注 = 18% / 22% / 10% / 15% / 20% / 15%。
# 窗口缩放时按同一比例重算，任何窗口尺寸下六列都在窗口内，且不允许手动拖动改宽
COLUMN_RATIOS = (("ip", "col_ip", 0.18, "w"), ("mac", "col_mac", 0.22, "center"),
                 ("ttl", "col_ttl", 0.10, "center"), ("delay", "col_delay", 0.15, "center"),
                 ("state", "col_state", 0.20, "center"), ("note", "col_note", 0.15, "center"))


def _icon():
    """返回 logo.ico 的绝对路径，兼容 PyInstaller 单文件打包。"""
    base = getattr(sys, "_MEIPASS", None) or getattr(sys, "_MEIPASS2", None) or os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base, "logo.ico")
    return path if os.path.isfile(path) else ""


def run_gui():
    import queue
    import tkinter as tk
    from tkinter import font as tkfont
    from tkinter import ttk, messagebox

    class App:
        def __init__(self, root):
            self.root = root
            self.lang = load_lang()                             # 记住上次的语言，默认英文
            self.queue = queue.Queue()
            self.busy = False
            self.seen = {}                  # ip(int) -> 已完成的原始行
            self.order = []                 # IPv4 整数数组，顺序即显示顺序
            self.next_show = 0              # 下一个可连续插入表格的 order 下标
            self.online = 0
            self._error_msg = ""
            self._cleared = False       # 点过“清空”为 True：状态栏显示“已清空”而不是“未执行扫描”
            self.adapters = []                                     # 先设为空，后台线程加载
            self.adapter_loaded = False
            self.netname_cache = {}                             # 网卡名 -> 网络名（取过就记住）
            self.netname_threads = []
            self.source_fallback = False                        # 源地址绑定不可用时为 True

            root.title(self.t("title"))
            root.geometry("780x500")
            root.minsize(660, 340)
            try:
                root.iconbitmap(_icon())
            except tk.TclError:
                pass

            style = ttk.Style()
            for theme in ("vista", "winnative", "xpnative"):     # Win7 默认 Aero 风格
                if theme in style.theme_names():
                    style.theme_use(theme)
                    break

            self.menubar = tk.Menu(root, tearoff=0)
            self.menu_program = tk.Menu(self.menubar, tearoff=0)
            self.menu_program.add_command(label=self.t("menu_about"), command=self.about)
            self.menu_program.add_separator()
            self.menu_program.add_command(label=self.t("menu_exit"), command=root.destroy)
            self.menubar.add_cascade(label=self.t("menu_program"), menu=self.menu_program)
            self.menu_language = tk.Menu(self.menubar, tearoff=0)
            self.menu_language.add_command(label=self.t("menu_switch"), command=self.toggle_lang)
            self.menubar.add_cascade(label=self.t("menu_language"), menu=self.menu_language)
            root.config(menu=self.menubar)
            self._apply_menu_labels()

            form = ttk.Frame(root, padding=(8, 6, 8, 2))
            form.pack(fill="x")
            self.first = tk.StringVar()
            self.last = tk.StringVar()
            self.timeout = tk.StringVar(value=str(DEFAULT_TIMEOUT))
            self.show_offline = tk.BooleanVar(value=False)
            self.ip_label = ttk.Label(form, text=self.t("ip_label"))
            self.ip_label.pack(side="left")
            ttk.Entry(form, textvariable=self.first, width=15).pack(side="left", padx=2)
            # 查找方向固定向右，不可改；就是个普通标签，不加边框
            ttk.Label(form, text=">>", width=3, anchor="center").pack(side="left", padx=2)
            ttk.Entry(form, textvariable=self.last, width=15).pack(side="left", padx=2)
            ttk.Entry(form, textvariable=self.timeout, width=5).pack(side="left", padx=2)
            self.timeout_label = ttk.Label(form, text=self.t("timeout_label"))
            self.timeout_label.pack(side="left")
            self.offline_chk = ttk.Checkbutton(form, text=self.t("show_offline"),
                                               variable=self.show_offline, command=self._render)
            self.offline_chk.pack(side="left", padx=8)
            self.scan_btn = ttk.Button(form, text=self.t("scan"), command=self.start)
            self.scan_btn.pack(side="right")
            self.clear_btn = ttk.Button(form, text=self.t("clear"), command=self.clear)
            self.clear_btn.pack(side="right", padx=4)

            # 底部一行：左边状态提示，右边网卡选择（标签 -> 下拉 -> 配置，靠窗口右下角）
            bottom = ttk.Frame(root, padding=(8, 0, 8, 6))
            bottom.pack(side="bottom", fill="x")
            # 先 pack 的在最右边：配置按钮 -> 下拉 -> 标签
            self.config_btn = ttk.Button(bottom, text=self.t("configure"),
                                         command=self.configure_adapter)
            self.config_btn.pack(side="right")
            self.adapter_box = ttk.Combobox(bottom, state="readonly", width=46)
            self.adapter_box.pack(side="right", padx=(4, 4))
            self.adapter_box.bind("<<ComboboxSelected>>", self.switch_adapter)
            self.adapter_label = ttk.Label(bottom, text=self.t("adapter_label"))
            self.adapter_label.pack(side="right")
            self.status = ttk.Label(bottom, foreground="#666666")
            self.status.pack(side="left")                   # 剩余横向空间都给状态栏

            body = ttk.Frame(root, padding=(8, 2, 8, 0))
            body.pack(fill="both", expand=True)
            # 列宽按比例给（见 COLUMN_RATIOS），随窗口变化重算，故 stretch 关掉
            self.tree = ttk.Treeview(body, columns=[c[0] for c in COLUMN_RATIOS],
                                     show="headings", selectmode="browse")
            for key, title, ratio, anchor in COLUMN_RATIOS:
                self.tree.heading(key, text=self.t(title))
                self.tree.column(key, width=max(20, int(ratio * 747)), anchor=anchor,
                                 stretch=False)
            self.tree.bind("<Configure>", self._fit_columns)
            self.tree.bind("<Button-1>", self._block_column_resize)
            self.tree.bind("<B1-Motion>", self._block_column_resize)
            scroll = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")
            self.tree.pack(side="left", fill="both", expand=True)
            self.tree.tag_configure("off", foreground="#888888")
            # 子线程加载网卡清单，完成后刷新下拉框；窗口先显示出来再等
            threading.Thread(target=self._load_adapters, daemon=True).start()
            self.root.after(100, self._poll_adapters)
            self._refresh_status()
            

        # ---------- 网卡 ----------
        def _default_adapter_index(self):
            """默认选系统首选源地址那块网卡（选路失败就用第一块）。"""
            ip = preferred_ip()
            for index, (_, address) in enumerate(self.adapters):
                if address == ip:
                    return index
            return 0

        def current_adapter(self):
            return self.adapters[self.adapter_box.current()] if self.adapters else ("", "")

        def select_adapter(self, index):
            """选中某块网卡：IP 输入框跟着换成它的 /24，并后台取它的网络名。
            没插网线的网卡（无地址）不改变网段，扫描时也就不绑定源地址。"""
            if not self.adapters:
                return
            index = max(0, min(index, len(self.adapters) - 1))
            name, address = self.adapters[index]
            self.adapter_box["values"] = self._adapter_items()
            self.adapter_box.current(index)
            if not address:
                return
            self.first.set(range_for(address)[0])
            self.last.set(range_for(address)[1])
            if name not in self.netname_cache:
                thread = threading.Thread(target=self._fetch_netname, args=(name,), daemon=True)
                self.netname_threads.append(thread)
                thread.start()
                self.root.after(200, self._poll_netname)

        def switch_adapter(self, _event=None):
            self.select_adapter(self.adapter_box.current())

        def configure_adapter(self):
            """“配置”按钮：打开当前所选网卡的属性页（改 IPv4 就在这里）。"""
            open_adapter_properties(self.current_adapter()[0])

        def _adapter_items(self):
            """下拉项：网卡名 (IP[, 网络名])；没地址的显示“未连接”。"""
            items = []
            for name, address in self.adapters:
                netname = self.netname_cache.get(name, "")
                info = ", ".join([address, netname] if netname else [address]) \
                    if address else self.t("disconnected")
                items.append("%s (%s)" % (name, info))
            return items

        def _fetch_netname(self, name):
            """子线程里问网络名（有线的 PowerShell 冷启动要几秒）。"""
            self.netname_cache[name] = network_name(name)

        def _poll_netname(self):
            self.netname_threads = [t for t in self.netname_threads if t.is_alive()]
            index = self.adapter_box.current()
            self.adapter_box["values"] = self._adapter_items()
            self.adapter_box.current(max(0, index))
            if self.netname_threads:
                self.root.after(200, self._poll_netname)

        def _load_adapters(self):
            """子线程加载网卡清单。"""
            try:
                self.adapters = adapters()
            except Exception:
                self.adapters = []
            self.adapter_loaded = True

        def _poll_adapters(self):
            """轮询网卡清单是否加载完毕，就绪后填充下拉框并自动选择默认网卡。"""
            if not self.adapter_loaded:
                self.root.after(100, self._poll_adapters)
                return
            self.adapter_box["values"] = self._adapter_items()
            self.select_adapter(self._default_adapter_index())
            self._refresh_status()

        # ---------- 语言 ----------
        def t(self, key):
            return TEXT[self.lang][key]

        def _apply_menu_labels(self):
            """菜单标题带 (P)/(L)，并把下划线放到括号里的字母上 —— Windows 下即 Alt+P / Alt+L。"""
            for index, key in ((0, "menu_program"), (1, "menu_language")):
                label = self.t(key)
                self.menubar.entryconfigure(index, label=label,
                                            underline=label.index("(") + 1)

        def toggle_lang(self):
            self.lang = "zh" if self.lang == "en" else "en"
            save_lang(self.lang)
            self.root.title(self.t("title"))
            self._apply_menu_labels()
            self.menu_program.entryconfigure(0, label=self.t("menu_about"))
            self.menu_program.entryconfigure(2, label=self.t("menu_exit"))
            self.menu_language.entryconfigure(0, label=self.t("menu_switch"))
            self.ip_label.config(text=self.t("ip_label"))
            self.timeout_label.config(text=self.t("timeout_label"))
            self.offline_chk.config(text=self.t("show_offline"))
            self.scan_btn.config(text=self.t("scan"))
            self.clear_btn.config(text=self.t("clear"))
            self.config_btn.config(text=self.t("configure"))
            self.adapter_box["values"] = self._adapter_items()   # “未连接”等文案跟着语言走
            self.adapter_box.current(max(0, self.adapter_box.current()))
            self.adapter_label.config(text=self.t("adapter_label"))
            self._refresh_status()
            for key, title in (("ip", "col_ip"), ("mac", "col_mac"), ("ttl", "col_ttl"),
                               ("delay", "col_delay"), ("state", "col_state"),
                               ("note", "col_note")):
                self.tree.heading(key, text=self.t(title))
            self._render()

        def about(self):
            """提示框居中在软件窗口中心。系统原生 messagebox 只会屏幕居中，
            所以这里自建一个 Toplevel，按主窗口几何算位置。"""
            top = tk.Toplevel(self.root)
            top.title(self.t("menu_about"))
            top.transient(self.root)                    # 归属主窗口（不单独出现在任务栏）
            top.resizable(False, False)
            try:
                top.iconbitmap(_icon())
            except tk.TclError:
                pass
            body = ttk.Frame(top, padding=(20, 16))
            body.pack(fill="both", expand=True)
            ttk.Label(body, text=self.t("about")).pack()
            # 发布页链接：蓝字加下划线，手型光标，点一下用默认浏览器打开
            link_font = tkfont.nametofont("TkDefaultFont").copy()
            link_font.configure(underline=True)
            link = tk.Label(body, text=self.t("release_page"), foreground="#0000EE",
                            font=link_font, cursor="hand2")
            link.pack(pady=(10, 0))
            link.bind("<Button-1>", lambda _event: webbrowser.open(RELEASE_URL))
            ok = ttk.Button(body, text="OK", width=10, command=top.destroy)
            ok.pack(pady=(14, 0))
            top.bind("<Return>", lambda _event: top.destroy())      # 键盘也能关
            top.bind("<Escape>", lambda _event: top.destroy())
            top.update_idletasks()                      # 先量出对话框自身尺寸
            x = self.root.winfo_rootx() + (self.root.winfo_width() - top.winfo_reqwidth()) // 2
            y = self.root.winfo_rooty() + (self.root.winfo_height() - top.winfo_reqheight()) // 2
            top.geometry("+%d+%d" % (max(0, x), max(0, y)))
            top.update_idletasks()
            # wm geometry 定的是窗口边框位置，winfo_root* 是客户区位置，差一个标题栏高度，补掉
            top.geometry("+%d+%d" % (max(0, x - (top.winfo_rootx() - top.winfo_x())),
                                     max(0, y - (top.winfo_rooty() - top.winfo_y()))))
            top.grab_set()
            top.focus_set()
            ok.focus_set()                                  # 焦点给 OK，回车即可关闭
            self.root.wait_window(top)

        # ---------- 列宽 ----------
        def _block_column_resize(self, event):
            """在表头分隔线上按下/拖动直接吃掉：不允许手动改列宽（改了会把后面的列挤出窗口）。"""
            if self.tree.identify_region(event.x, event.y) == "separator":
                return "break"

        def _fit_columns(self, _event=None):
            """按比例重算列宽，最后一列吃掉余量：任何窗口尺寸下六列都在窗口内。"""
            width = self.tree.winfo_width()
            if width < 120:                     # 窗口还没布局好，等下一次 Configure
                return
            used = 0
            for index, (key, _, ratio, _) in enumerate(COLUMN_RATIOS):
                if index == len(COLUMN_RATIOS) - 1:
                    column = max(20, width - used - 4)      # 余量给最后一列，右侧不留空隙
                else:
                    column = max(20, int(ratio * width))
                    used += column
                self.tree.column(key, width=column)

        # ---------- 显示 ----------
        def _refresh_status(self):
            """更新底部状态栏：扫描进度 / 就绪统计 / 未执行扫描 / 已清空 / 错误信息。"""
            suffix = ""
            if self._error_msg:
                suffix = self.t("status_error") % self._error_msg
            elif self.busy:
                suffix = self.t("status_scanning") % (len(self.seen), len(self.order))
            elif self.order:
                suffix = self.t("status_ready") % self.online
            else:                                   # 没扫过 / 清空过：都不是“就绪”
                suffix = self.t("status_cleared") if self._cleared else self.t("status_idle")
            if self.source_fallback:
                suffix += "  · " + self.t("no_source")
            self.status.config(text=suffix)

        def _view(self, row):
            """原始行 -> 表格显示值（状态和备注按当前语言翻译）。"""
            return (row[0], row[1] or "-", row[2] or "-", row[3] or "-",
                    self.t("online") if row[4] else self.t("offline"),
                    self.t("local") if row[5] else "")

        def _render(self):
            """按 order 顺序整表重建（语言切换、勾选显示离线、扫描结束都用它）。"""
            self.tree.delete(*self.tree.get_children())
            self.online = 0
            for index, ip in enumerate(self.order):
                row = self.seen.get(ip)
                if not row:
                    continue
                if row[4]:
                    self.online += 1
                elif not self.show_offline.get():
                    continue
                self.tree.insert("", "end", iid=str(ip), values=self._view(row),
                                 tags=() if row[4] else ("off",))
            self._refresh_status()

        # ---------- 交互 ----------
        def start(self):
            if self.busy:
                return
            try:
                hosts = parse_range(self.first.get(), self.last.get())
                timeout_ms = max(10, min(10000, int(self.timeout.get())))
            except ValueError as exc:
                messagebox.showerror(self.t("bad_input"), str(exc), parent=self.root)
                return
            self.timeout.set(str(timeout_ms))
            # 用所选网卡做源地址探测；网卡没地址或绑不上就退回系统默认路由（不让结果全空）
            source = self.current_adapter()[1]
            self.source_fallback = not source
            if source and not _source_ok(source, timeout_ms):
                source = ""
                self.source_fallback = True
            self._error_msg = ""
            self.clear()
            self.order = hosts
            self._cleared = False                   # 本次是扫描，不是清空
            self.busy = True
            self.scan_btn.config(state="disabled")
            self._refresh_status()                  # 先把「搜索中 0/N」显示出来，避免点了没反应
            threading.Thread(target=self._work,
                             args=(hosts, timeout_ms, source), daemon=True).start()
            self.root.after(100, self._drain)

        def clear(self):
            if self.busy:
                return
            self.seen, self.order = {}, []
            self.next_show = 0
            self.online = 0
            self._error_msg = ""
            self._cleared = True
            self.tree.delete(*self.tree.get_children())
            self._refresh_status()

        # ---------- 子线程 ----------
        def _work(self, hosts, timeout_ms, source):
            try:
                # Windows 下 GUI 只需边扫边收行，不再额外构建并回传整份结果列表。
                rows = scan(hosts, timeout_ms,
                            on_row=lambda index, row: self.queue.put(("row", index, row)),
                            source=source, collect=not WINDOWS)
            except Exception as exc:                       # 子线程异常带回主线程显示
                self.queue.put(("error", repr(exc)))
                return
            self.queue.put(("done", rows))

        # ---------- 主线程 ----------
        def _drain(self):
            try:
                while True:
                    item = self.queue.get_nowait()
                    kind = item[0]
                    if kind == "row":
                        _, index, payload = item
                        self._add_row(index, payload)
                    elif kind == "done":
                        payload = item[1] if len(item) > 1 else None
                        if payload:
                            self.seen = {_ip_to_int(row[0]): row for row in payload}
                            self.online = sum(1 for row in payload if row[4])
                        self.busy = False
                        self.scan_btn.config(state="normal")
                        self._render()
                    else:
                        self.busy = False
                        self._error_msg = item[1]
                        self.scan_btn.config(state="normal")
                        self._refresh_status()
                        messagebox.showerror(self.t("scan_failed"), item[1], parent=self.root)
            except queue.Empty:
                pass
            if self.busy:                                   # 扫描期间保持排空队列
                self.root.after(100, self._drain)

        def _add_row(self, index, row):
            """边扫边填：按顺序追加已完成行，MAC 最终补齐时更新已插入的行。"""
            ip = self.order[index]
            if ip in self.seen:
                self.seen[ip] = row
                try:
                    self.tree.item(str(ip), values=self._view(row))
                except tk.TclError:
                    pass
                self._refresh_status()
                return
            self.seen[ip] = row
            if row[4]:
                self.online += 1
            while self.next_show < len(self.order) and self.order[self.next_show] in self.seen:
                current = self.seen[self.order[self.next_show]]
                if current[4] or self.show_offline.get():
                    self.tree.insert("", "end", iid=str(self.order[self.next_show]),
                                     values=self._view(current),
                                     tags=() if current[4] else ("off",))
                self.next_show += 1
            self._refresh_status()

    root = tk.Tk()
    App(root)
    root.mainloop()


def main(argv):
    if len(argv) >= 3:
        try:
            hosts = parse_range(argv[1], argv[2])
        except ValueError as exc:
            print("bad arguments:", exc)
            return 2
        started = time.perf_counter()
        found = 0
        for ip, mac, ttl, delay, online, is_local in scan(hosts):
            if online:
                found += 1
                print("%-16s %-17s TTL=%-4s %s ms%s"
                      % (ip, mac or "-", ttl, delay, "   [This PC]" if is_local else ""))
        print("Scan time: %d ms   Online: %d/%d"
              % ((time.perf_counter() - started) * 1000, found, len(hosts)))
        return 0
    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
