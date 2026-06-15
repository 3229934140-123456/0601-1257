import re
import os
import glob
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import List, Dict, Optional, Iterator, Tuple


LOG_FORMATS = {
    "combined": re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+|-)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    ),
    "common": re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+|-)'
    ),
}

TIME_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%d %H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
]


class LogEntry:
    def __init__(self, raw: str, data: Dict[str, str], source: str = ""):
        self.raw = raw
        self.data = data
        self.source = source
        self._parsed_time = None

    @property
    def ip(self) -> str:
        return self.data.get("ip", "")

    @property
    def status(self) -> int:
        try:
            return int(self.data.get("status", 0))
        except ValueError:
            return 0

    @property
    def method(self) -> str:
        return self.data.get("method", "")

    @property
    def path(self) -> str:
        return self.data.get("path", "")

    @property
    def user_agent(self) -> str:
        return self.data.get("user_agent", "")

    @property
    def referer(self) -> str:
        return self.data.get("referer", "")

    @property
    def size(self) -> int:
        try:
            val = self.data.get("size", "0")
            if val == "-":
                return 0
            return int(val)
        except (ValueError, TypeError):
            return 0

    @property
    def timestamp(self) -> Optional[datetime]:
        if self._parsed_time is None:
            time_str = self.data.get("time", "")
            for fmt in TIME_FORMATS:
                try:
                    self._parsed_time = datetime.strptime(time_str, fmt)
                    break
                except ValueError:
                    continue
        return self._parsed_time

    def get(self, key: str, default: str = "") -> str:
        return self.data.get(key, default)


class LogParser:
    def __init__(self, log_format: str = "combined"):
        self.log_format = log_format
        self.pattern = LOG_FORMATS.get(log_format, LOG_FORMATS["combined"])

    def parse_line(self, line: str, source: str = "") -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None
        match = self.pattern.match(line)
        if match:
            return LogEntry(raw=line, data=match.groupdict(), source=source)
        return None

    def parse_file(self, filepath: str) -> Iterator[LogEntry]:
        source = os.path.basename(filepath)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    entry = self.parse_line(line, source)
                    if entry:
                        yield entry
        except IOError as e:
            print(f"Error reading file {filepath}: {e}")

    def parse_files(self, filepaths: List[str]) -> Iterator[LogEntry]:
        for filepath in filepaths:
            yield from self.parse_file(filepath)


def resolve_paths(paths: List[str]) -> List[str]:
    files = []
    for path in paths:
        if os.path.isfile(path):
            files.append(os.path.abspath(path))
        elif os.path.isdir(path):
            for root, _, filenames in os.walk(path):
                for fname in filenames:
                    if fname.endswith((".log", ".txt")):
                        files.append(os.path.abspath(os.path.join(root, fname)))
        else:
            matched = glob.glob(path)
            files.extend(os.path.abspath(m) for m in matched if os.path.isfile(m))
    return sorted(set(files))


def _parse_datetime(s: str) -> Optional[datetime]:
    """解析日期时间字符串，返回带时区或不带时区的datetime"""
    if not s:
        return None
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _cmp_datetime(a: datetime, b: datetime) -> int:
    """安全比较两个datetime，自动处理时区差异。
    当一个有tz一个无时，将naive一方解释为与aware一方相同的时区（而非默认UTC），
    以符合值班人员'按日志显示时间'筛选的直觉。
    """
    a_aware = a.tzinfo is not None and a.tzinfo.utcoffset(a) is not None
    b_aware = b.tzinfo is not None and b.tzinfo.utcoffset(b) is not None
    if a_aware and not b_aware:
        b = b.replace(tzinfo=a.tzinfo)
    elif b_aware and not a_aware:
        a = a.replace(tzinfo=b.tzinfo)
    if a < b:
        return -1
    elif a > b:
        return 1
    return 0


def filter_by_time(entries: Iterator[LogEntry], start: Optional[str] = None,
                   end: Optional[str] = None) -> Iterator[LogEntry]:
    start_dt = _parse_datetime(start) if start else None
    end_dt = _parse_datetime(end) if end else None

    for entry in entries:
        ts = entry.timestamp
        if ts is None:
            continue
        if start_dt and _cmp_datetime(ts, start_dt) < 0:
            continue
        if end_dt and _cmp_datetime(ts, end_dt) > 0:
            continue
        yield entry


def filter_by_keyword(entries: Iterator[LogEntry], keyword: str,
                      field: Optional[str] = None) -> Iterator[LogEntry]:
    kw = keyword.lower()
    for entry in entries:
        if field:
            if kw in entry.get(field).lower():
                yield entry
        else:
            if kw in entry.raw.lower():
                yield entry


def filter_by_regex(entries: Iterator[LogEntry], pattern: str,
                    field: Optional[str] = None) -> Iterator[LogEntry]:
    regex = re.compile(pattern, re.IGNORECASE)
    for entry in entries:
        if field:
            if regex.search(entry.get(field)):
                yield entry
        else:
            if regex.search(entry.raw):
                yield entry


def filter_by_status(entries: Iterator[LogEntry],
                     status_codes: List[int]) -> Iterator[LogEntry]:
    for entry in entries:
        if entry.status in status_codes:
            yield entry


def filter_by_ip(entries: Iterator[LogEntry],
                 ip_list: List[str]) -> Iterator[LogEntry]:
    for entry in entries:
        if entry.ip in ip_list:
            yield entry


def paginate(entries: List[LogEntry], page: int = 1,
             page_size: int = 20) -> Tuple[List[LogEntry], int, int]:
    total = len(entries)
    total_pages = (total + page_size - 1) // page_size
    start = (page - 1) * page_size
    end = start + page_size
    return entries[start:end], total, total_pages


def aggregate_by_ip(entries: List[LogEntry]) -> List[Dict]:
    stats = defaultdict(lambda: {"count": 0, "statuses": defaultdict(int),
                                 "methods": defaultdict(int), "paths": set()})
    for entry in entries:
        ip = entry.ip
        stats[ip]["count"] += 1
        stats[ip]["statuses"][entry.status] += 1
        stats[ip]["methods"][entry.method] += 1
        stats[ip]["paths"].add(entry.path)
    result = []
    for ip, data in stats.items():
        result.append({
            "ip": ip,
            "count": data["count"],
            "statuses": dict(data["statuses"]),
            "methods": dict(data["methods"]),
            "unique_paths": len(data["paths"]),
        })
    result.sort(key=lambda x: x["count"], reverse=True)
    return result


def aggregate_by_status(entries: List[LogEntry]) -> List[Dict]:
    stats = defaultdict(lambda: {"count": 0, "ips": set()})
    for entry in entries:
        status = entry.status
        stats[status]["count"] += 1
        stats[status]["ips"].add(entry.ip)
    result = []
    for status, data in stats.items():
        result.append({
            "status": status,
            "count": data["count"],
            "unique_ips": len(data["ips"]),
        })
    result.sort(key=lambda x: x["count"], reverse=True)
    return result


def aggregate_by_path(entries: List[LogEntry], limit: int = 20) -> List[Dict]:
    stats = defaultdict(lambda: {"count": 0, "ips": set(), "statuses": defaultdict(int)})
    for entry in entries:
        path = entry.path
        stats[path]["count"] += 1
        stats[path]["ips"].add(entry.ip)
        stats[path]["statuses"][entry.status] += 1
    result = []
    for path, data in stats.items():
        result.append({
            "path": path,
            "count": data["count"],
            "unique_ips": len(data["ips"]),
            "statuses": dict(data["statuses"]),
        })
    result.sort(key=lambda x: x["count"], reverse=True)
    return result[:limit]


def get_session_trace(entries: List[LogEntry], ip: str) -> List[LogEntry]:
    session_entries = [e for e in entries if e.ip == ip]
    session_entries.sort(key=lambda e: e.timestamp or datetime.min)
    return session_entries


def detect_high_frequency(entries: List[LogEntry], threshold: int = 100,
                          window_seconds: int = 60) -> List[Dict]:
    ip_times = defaultdict(list)
    for entry in entries:
        if entry.timestamp:
            ip_times[entry.ip].append(entry.timestamp)

    result = []
    for ip, times in ip_times.items():
        times.sort()
        if len(times) < threshold:
            continue
        left = 0
        for right in range(len(times)):
            while (times[right] - times[left]).total_seconds() > window_seconds:
                left += 1
            if right - left + 1 >= threshold:
                result.append({
                    "ip": ip,
                    "request_count": len(times),
                    "peak_count": right - left + 1,
                    "peak_start": times[left].strftime("%Y-%m-%d %H:%M:%S"),
                    "peak_end": times[right].strftime("%Y-%m-%d %H:%M:%S"),
                })
                break
    result.sort(key=lambda x: x["peak_count"], reverse=True)
    return result


def compute_summary(entries: List[LogEntry]) -> Dict:
    total = len(entries)
    unique_ips = len(set(e.ip for e in entries))
    unique_paths = len(set(e.path for e in entries))

    status_counts = defaultdict(int)
    method_counts = defaultdict(int)
    total_size = 0

    for entry in entries:
        status_counts[entry.status] += 1
        method_counts[entry.method] += 1
        total_size += entry.size

    first_time = None
    last_time = None
    for entry in entries:
        ts = entry.timestamp
        if ts:
            if first_time is None or ts < first_time:
                first_time = ts
            if last_time is None or ts > last_time:
                last_time = ts

    return {
        "total_requests": total,
        "unique_ips": unique_ips,
        "unique_paths": unique_paths,
        "status_distribution": dict(status_counts),
        "method_distribution": dict(method_counts),
        "total_bytes": total_size,
        "time_range_start": first_time.strftime("%Y-%m-%d %H:%M:%S") if first_time else "N/A",
        "time_range_end": last_time.strftime("%Y-%m-%d %H:%M:%S") if last_time else "N/A",
        "avg_request_size": total_size // total if total > 0 else 0,
    }
