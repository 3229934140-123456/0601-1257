import os
import csv
import json
from datetime import datetime
from typing import List, Dict, Optional
from .parser import LogEntry
from .rules import RuleMatch


class Exporter:
    def __init__(self, export_dir: Optional[str] = None):
        self.export_dir = export_dir or os.path.join(os.path.expanduser("~"), "logalyzer_exports")
        os.makedirs(self.export_dir, exist_ok=True)

    def _generate_filename(self, prefix: str, ext: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{prefix}_{timestamp}.{ext}"

    def export_entries_csv(self, entries: List[LogEntry],
                           filename: Optional[str] = None) -> str:
        if not filename:
            filename = self._generate_filename("logs", "csv")
        filepath = os.path.join(self.export_dir, filename)

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow([
                "时间", "IP", "方法", "路径", "状态码",
                "大小", "Referer", "User-Agent", "来源文件"
            ])
            for entry in entries:
                ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else ""
                writer.writerow([
                    ts,
                    entry.ip,
                    entry.method,
                    entry.path,
                    entry.status,
                    entry.size,
                    entry.referer,
                    entry.user_agent,
                    entry.source,
                ])
        return filepath

    def export_entries_txt(self, entries: List[LogEntry],
                           filename: Optional[str] = None) -> str:
        if not filename:
            filename = self._generate_filename("logs", "txt")
        filepath = os.path.join(self.export_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(entry.raw + "\n")
        return filepath

    def export_matches_csv(self, matches: List[RuleMatch],
                           filename: Optional[str] = None) -> str:
        if not filename:
            filename = self._generate_filename("alerts", "csv")
        filepath = os.path.join(self.export_dir, filename)

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow([
                "时间", "IP", "规则名称", "严重级别", "分类",
                "详情", "状态码", "路径", "原始日志"
            ])
            for match in matches:
                ts = match.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if match.entry.timestamp else ""
                writer.writerow([
                    ts,
                    match.entry.ip,
                    match.rule.name,
                    match.rule.severity,
                    match.rule.category,
                    match.detail,
                    match.entry.status,
                    match.entry.path,
                    match.entry.raw,
                ])
        return filepath

    def export_summary_json(self, summary: Dict,
                            filename: Optional[str] = None) -> str:
        if not filename:
            filename = self._generate_filename("summary", "json")
        filepath = os.path.join(self.export_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
        return filepath

    def export_report_txt(self, summary: Dict, matches: List[RuleMatch] = None,
                          filename: Optional[str] = None) -> str:
        if not filename:
            filename = self._generate_filename("report", "txt")
        filepath = os.path.join(self.export_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write("         日志分析排查报告\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("-" * 40 + "\n")
            f.write("一、流量概览\n")
            f.write("-" * 40 + "\n")
            f.write(f"  总请求数:     {summary.get('total_requests', 0)}\n")
            f.write(f"  独立IP数:     {summary.get('unique_ips', 0)}\n")
            f.write(f"  独立路径数:   {summary.get('unique_paths', 0)}\n")
            f.write(f"  总流量:       {_format_size(summary.get('total_bytes', 0))}\n")
            f.write(f"  平均请求大小: {_format_size(summary.get('avg_request_size', 0))}\n")
            f.write(f"  时间范围:     {summary.get('time_range_start', 'N/A')} ~ {summary.get('time_range_end', 'N/A')}\n\n")

            f.write("-" * 40 + "\n")
            f.write("二、状态码分布\n")
            f.write("-" * 40 + "\n")
            status_dist = summary.get("status_distribution", {})
            for status in sorted(status_dist.keys()):
                count = status_dist[status]
                bar = "█" * min(count // max(status_dist.values()) * 30, 30) if status_dist else ""
                f.write(f"  {status}: {count:6d} {bar}\n")
            f.write("\n")

            f.write("-" * 40 + "\n")
            f.write("三、HTTP方法分布\n")
            f.write("-" * 40 + "\n")
            method_dist = summary.get("method_distribution", {})
            for method in sorted(method_dist.keys()):
                count = method_dist[method]
                f.write(f"  {method}: {count}\n")
            f.write("\n")

            if matches:
                f.write("-" * 40 + "\n")
                f.write(f"四、异常检测 ({len(matches)} 条告警)\n")
                f.write("-" * 40 + "\n\n")

                by_severity: Dict[str, int] = {}
                by_rule: Dict[str, int] = {}
                for m in matches:
                    by_severity[m.rule.severity] = by_severity.get(m.rule.severity, 0) + 1
                    by_rule[m.rule.name] = by_rule.get(m.rule.name, 0) + 1

                f.write("  按严重级别统计:\n")
                for sev in ["critical", "high", "medium", "low", "warning"]:
                    if sev in by_severity:
                        f.write(f"    {sev:10s}: {by_severity[sev]} 条\n")
                f.write("\n")

                f.write("  按规则统计:\n")
                for rule_name, count in sorted(by_rule.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"    {rule_name:30s}: {count} 条\n")
                f.write("\n")

                critical_matches = [m for m in matches if m.rule.severity in ("critical", "high")]
                if critical_matches:
                    f.write("  高危告警详情 (前20条):\n\n")
                    for i, m in enumerate(critical_matches[:20], 1):
                        ts = m.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if m.entry.timestamp else ""
                        f.write(f"  [{i}] [{m.rule.severity.upper()}] {m.rule.name}\n")
                        f.write(f"      时间: {ts}\n")
                        f.write(f"      IP:   {m.entry.ip}\n")
                        f.write(f"      路径: {m.entry.path}\n")
                        f.write(f"      详情: {m.detail}\n")
                        f.write(f"      原始: {m.entry.raw[:100]}...\n\n")

            f.write("=" * 60 + "\n")
            f.write("                   报告结束\n")
            f.write("=" * 60 + "\n")

        return filepath

    def export_top_ips_csv(self, ip_stats: List[Dict],
                           filename: Optional[str] = None) -> str:
        if not filename:
            filename = self._generate_filename("top_ips", "csv")
        filepath = os.path.join(self.export_dir, filename)

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "请求数", "独立路径数", "状态码分布", "方法分布"])
            for stat in ip_stats:
                writer.writerow([
                    stat["ip"],
                    stat["count"],
                    stat["unique_paths"],
                    str(stat["statuses"]),
                    str(stat["methods"]),
                ])
        return filepath


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
