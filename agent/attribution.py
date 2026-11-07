"""Attribute honeypot log lines to a real source IP.

Honeypot logs only show the Docker gateway as the client address (Docker relays published ports). The pcap has the
real source, so a log line is matched to the source whose connection time in the pcap is closest to the line's time.
"""
import bisect
import shutil
import subprocess
from pathlib import Path

SERVICE_PORTS = {"ssh": ("22", "2222"), "mysql": ("3306",), "smb": ("445", "4445"), "ftp": ("21", "23")}
SKEW = 1.0      # a container's log clock can run a little ahead of the capture clock: the SYN may follow its own log line
ROOT = Path(__file__).resolve().parent.parent


def host_ip():
    try:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            if line.startswith("HOST_IP="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "10.10.10.1"


def target_ip(service):
    """Address a honeypot listens on: a spawned decoy has its own (the number at the end of its name), the base lab answers
    on the host address. A routine check of another address on the same port is then not a candidate source."""
    host = host_ip()
    tail = service.rsplit("-", 1)[-1]
    if service.startswith("decoy-") and tail.isdigit():
        return f"{host.rsplit('.', 1)[0]}.{tail}"
    return host


def _tshark():
    return shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"


def service_times(pcaps):
    """{service: sorted [(epoch, source ip, destination ip)]} for SSH and MySQL connection attempts and for HTTP requests."""
    times = {"ssh": [], "mysql": [], "smb": [], "ftp": [], "http": []}
    ports = {p: svc for svc, ps in SERVICE_PORTS.items() for p in ps}
    flt = "(tcp.flags.syn==1 && tcp.flags.ack==0 && (tcp.dstport==22 || tcp.dstport==2222 || tcp.dstport==3306 || tcp.dstport==445 || tcp.dstport==4445 || tcp.dstport==21 || tcp.dstport==23)) || http.request"
    for p in pcaps:
        out = subprocess.run([_tshark(), "-r", str(p), "-Y", flt, "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src",
                              "-e", "tcp.dstport", "-e", "http.request.method", "-e", "ip.dst"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            t, src, port, method, dst = (line.split("\t") + ["", "", "", "", ""])[:5]
            if t and src:
                times["http" if method else ports.get(port, "ssh")].append((float(t), src, dst))
    for v in times.values():
        v.sort()
    return times


def nearest_source(series, ts, tol, dst=None):
    """Source whose connection time is closest to ts (None if none within tol seconds). With dst, only connections to that address count."""
    if dst:
        series = [x for x in series if len(x) > 2 and x[2] == dst]
    i = bisect.bisect_left(series, (ts, ""))
    best = None
    for j in (i - 1, i):
        if 0 <= j < len(series) and abs(series[j][0] - ts) <= tol and (best is None or abs(series[j][0] - ts) < abs(best[0] - ts)):
            best = series[j]
    return best[1] if best else None


def http_requests_matching(pcaps, fragments):
    """[(epoch, source ip, uri)] for HTTP requests whose URI contains any fragment (used to see who fetched a lure)."""
    out = []
    for p in pcaps:
        res = subprocess.run([_tshark(), "-r", str(p), "-Y", "http.request", "-T", "fields", "-e", "frame.time_epoch",
                              "-e", "ip.src", "-e", "http.request.uri"], capture_output=True, text=True).stdout
        for line in res.splitlines():
            t, src, uri = (line.split("\t") + ["", "", ""])[:3]
            if t and src and any(f in uri for f in fragments):
                out.append((float(t), src, uri))
    return sorted(out)


def attribute_hit(hit, times):
    """Real source IP of a honeytoken use. Uses the session's connect time when known (it is close to the SYN); otherwise
    the latest connection to that service in the 4 minutes before the login."""
    service = hit.get("service", "")
    if hit["kind"] == "mysql_credential":
        series = times["mysql"]
    elif service.startswith("opencanary") or service.startswith("decoy-ftp"):
        series = times["ftp"]            # the same login tried on the FTP/Telnet honeypot (credential reuse)
    else:
        series = times["ssh"]
    dst = target_ip(service)
    if hit.get("connect_ts") is not None:
        return nearest_source(series, hit["connect_ts"], 3, dst)
    prior = [x for x in series if hit["ts"] - 240 <= x[0] <= hit["ts"] + SKEW and len(x) > 2 and x[2] == dst]    # the fake MySQL can take ~2 min to answer a login
    return prior[-1][1] if prior else None
