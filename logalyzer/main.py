import sys
import os
import re
import time
from datetime import datetime
from collections import deque, defaultdict
from typing import List, Optional

import click
from colorama import init, Fore, Style

from .parser import (
    LogParser, resolve_paths, filter_by_time, filter_by_keyword,
    filter_by_regex, filter_by_status, filter_by_ip, paginate,
    aggregate_by_ip, aggregate_by_status, aggregate_by_path,
    get_session_trace, detect_high_frequency, compute_summary,
    LogEntry
)
from .rules import RuleEngine, RuleMatch
from .config import ConfigManager
from .exporter import Exporter, _format_size, group_matches, get_disposition, risk_level


init(autoreset=True)

SEVERITY_COLORS = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "warning": Fore.MAGENTA,
}

SEVERITY_TAGS = {
    "critical": "[严重]",
    "high": "[高危]",
    "medium": "[中危]",
    "low": "[低危]",
    "warning": "[警告]",
}


def _highlight_keywords(text: str, keywords: List[str]) -> str:
    if not keywords:
        return text
    result = text
    for kw in keywords:
        if not kw:
            continue
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        result = pattern.sub(
            lambda m: Fore.YELLOW + Style.BRIGHT + m.group(0) + Style.RESET_ALL,
            result
        )
    return result


def _print_entry(entry: LogEntry, idx: int = 0, keywords: List[str] = None,
                 show_all: bool = False):
    ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else "N/A"
    status = str(entry.status)
    if entry.status >= 500:
        status_colored = Fore.RED + status + Style.RESET_ALL
    elif entry.status >= 400:
        status_colored = Fore.YELLOW + status + Style.RESET_ALL
    elif entry.status >= 300:
        status_colored = Fore.CYAN + status + Style.RESET_ALL
    else:
        status_colored = Fore.GREEN + status + Style.RESET_ALL

    raw = entry.raw
    if keywords:
        raw = _highlight_keywords(raw, keywords)

    if show_all:
        click.echo(f"  [{idx}] {Fore.CYAN}{ts}{Style.RESET_ALL}  "
                   f"{entry.ip:15s}  {entry.method:6s}  "
                   f"{status_colored}  {_format_size(entry.size):>8s}  "
                   f"{entry.path}")
        if entry.user_agent:
            click.echo(f"       UA: {entry.user_agent}")
        if entry.referer:
            click.echo(f"       Referer: {entry.referer}")
    else:
        click.echo(f"  [{idx}] {Fore.CYAN}{ts}{Style.RESET_ALL}  "
                   f"{entry.ip:15s}  {entry.method:6s}  "
                   f"{status_colored}  {_format_size(entry.size):>8s}  "
                   f"{entry.path}")


def _load_entries(paths: List[str], log_format: str, start: str = None,
                  end: str = None, keyword: str = None, regex: str = None,
                  status_codes: List[int] = None, ips: List[str] = None,
                  field: str = None) -> List[LogEntry]:
    files = resolve_paths(paths)
    if not files:
        click.echo(Fore.RED + "未找到任何日志文件" + Style.RESET_ALL)
        sys.exit(1)

    parser = LogParser(log_format=log_format)
    entries = list(parser.parse_files(files))

    if not entries:
        click.echo(Fore.RED + "未能解析任何日志条目" + Style.RESET_ALL)
        sys.exit(1)

    if start or end:
        entries = list(filter_by_time(iter(entries), start, end))

    if keyword:
        entries = list(filter_by_keyword(iter(entries), keyword, field))

    if regex:
        entries = list(filter_by_regex(iter(entries), regex, field))

    if status_codes:
        entries = list(filter_by_status(iter(entries), status_codes))

    if ips:
        entries = list(filter_by_ip(iter(entries), ips))

    return entries


@click.group()
@click.version_option(version="1.0.0", prog_name="logalyzer")
@click.pass_context
def cli(ctx):
    """日志分析平台命令行工具 - 供安全值班人员快速筛查异常访问日志"""
    ctx.ensure_object(dict)
    ctx.obj["config"] = ConfigManager()


@cli.command()
@click.argument("paths", nargs=-1)
@click.option("-f", "--format", "log_format", default=None,
              help="日志格式 (combined/common)，默认: combined")
@click.option("--start", default=None, help="开始时间 (如: 2024-01-01 00:00:00)")
@click.option("--end", default=None, help="结束时间 (如: 2024-01-02 00:00:00)")
@click.option("-r", "--rules", "rules_file", default=None, help="异常规则配置文件路径")
@click.option("--no-default-rules", is_flag=True, help="不加载内置规则")
@click.option("--severity", default=None,
              help="只显示指定严重级别的告警 (critical/high/medium/low)")
@click.option("--category", default=None, help="只显示指定分类的告警")
@click.option("-n", "--limit", default=20, help="显示的告警数量，默认: 20")
@click.option("--page", default=1, help="页码，默认: 1")
@click.option("--page-size", default=None, type=int, help="每页大小")
@click.option("-k", "--highlight", multiple=True, help="关键字高亮，可多次指定")
@click.option("--summary/--no-summary", default=True, help="是否显示摘要")
@click.option("--export", "export_file", default=None, help="导出结果到CSV文件")
@click.option("--report", "report_file", default=None, help="生成排查报告")
@click.option("--profile", default=None, help="使用配置档案")
@click.pass_context
def scan(ctx, paths, log_format, start, end, rules_file, no_default_rules,
         severity, category, limit, page, page_size, highlight, summary,
         export_file, report_file, profile):
    """扫描日志，检测异常访问和攻击行为"""
    config = ctx.obj["config"]

    if profile:
        prof = config.load_profile(profile)
        if prof:
            if not paths and "paths" in prof:
                paths = tuple(prof["paths"])
            if not log_format and "format" in prof:
                log_format = prof["format"]
            if not start and "start" in prof:
                start = prof["start"]
            if not end and "end" in prof:
                end = prof["end"]
            if not rules_file and "rules_file" in prof:
                rules_file = prof["rules_file"]
        else:
            click.echo(Fore.YELLOW + f"警告: 配置档案 '{profile}' 不存在" + Style.RESET_ALL)

    log_format = log_format or config.get("default_format", "combined")
    page_size = page_size or config.get("page_size", 20)

    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    entries = _load_entries(list(paths), log_format, start, end)

    engine = RuleEngine()
    if not no_default_rules:
        engine.load_default_rules()

    if rules_file:
        engine.load_rules_file(rules_file)
    else:
        for rf in config.get("rules_files", []):
            engine.load_rules_file(rf)

    if not engine.rules:
        click.echo(Fore.YELLOW + "警告: 未加载任何规则" + Style.RESET_ALL)

    matches = engine.scan_entries(entries)

    if severity:
        matches = [m for m in matches if m.rule.severity == severity]
    if category:
        matches = [m for m in matches if m.rule.category == category]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "warning": 4}
    matches.sort(key=lambda m: (severity_order.get(m.rule.severity, 99),
                                -m.entry.status if m.entry.timestamp else 0))

    if summary:
        rules_summary = engine.get_rules_summary()
        match_summary = engine.match_summary(matches)
        data_summary = compute_summary(entries)

        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "  日志扫描结果" + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
        click.echo()
        click.echo(f"  解析日志条目: {data_summary['total_requests']} 条")
        click.echo(f"  加载规则数量: {rules_summary['enabled']} 条")
        critical_count = match_summary["by_severity"].get("critical", 0)
        high_count = match_summary["by_severity"].get("high", 0)
        risk = risk_level(match_summary["total_matches"], critical_count, high_count)
        risk_color = Fore.RED + Style.BRIGHT if risk in ("极高", "高") else (
            Fore.YELLOW if risk == "中" else Fore.GREEN)
        click.echo(f"  告警总数:     {Fore.RED if match_summary['total_matches'] > 0 else ''}"
                   f"{match_summary['total_matches']} 条{Style.RESET_ALL}"
                   f"   {risk_color}风险等级: {risk}{Style.RESET_ALL}")
        click.echo(f"  涉及IP数:     {match_summary['unique_ips']} 个")
        click.echo(f"  时间范围:     {data_summary['time_range_start']} ~ "
                   f"{data_summary['time_range_end']}")
        click.echo()

        click.echo(Fore.YELLOW + "  按严重级别:" + Style.RESET_ALL)
        for sev in ["critical", "high", "medium", "low", "warning"]:
            count = match_summary["by_severity"].get(sev, 0)
            if count > 0:
                color = SEVERITY_COLORS.get(sev, "")
                tag = SEVERITY_TAGS.get(sev, "")
                click.echo(f"    {color}{tag}{sev:10s}{Style.RESET_ALL}: {count} 条")
        click.echo()

        _print_scan_summary(matches)
        click.echo()

    total_matches = len(matches)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_matches = matches[start_idx:end_idx]

    if total_matches > 0:
        click.echo(Fore.YELLOW + Style.BRIGHT + f"  告警列表 (第{page}页，共{total_matches}条):" + Style.RESET_ALL)
        click.echo()

        for i, match in enumerate(page_matches, start=start_idx + 1):
            sev_color = SEVERITY_COLORS.get(match.rule.severity, "")
            ts = match.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if match.entry.timestamp else "N/A"
            entry_display = match.entry.raw
            if highlight:
                entry_display = _highlight_keywords(entry_display, list(highlight))

            click.echo(f"  [{i}] {sev_color}[{match.rule.severity.upper()}] "
                       f"{match.rule.name}{Style.RESET_ALL}")
            click.echo(f"       {Fore.CYAN}{ts}{Style.RESET_ALL}  "
                       f"{match.entry.ip:15s}  {match.entry.method:6s}  "
                       f"{match.entry.status}  {match.entry.path}")
            click.echo(f"       {Fore.MAGENTA}详情:{Style.RESET_ALL} {match.detail}")
            click.echo()

        total_pages = (total_matches + page_size - 1) // page_size
        if total_pages > 1:
            click.echo(f"  第 {page}/{total_pages} 页 | "
                       f"共 {total_matches} 条告警 | "
                       f"每页 {page_size} 条")

    if export_file:
        exporter = Exporter(export_dir=config.get("export_dir"))
        filepath = exporter.export_matches_csv(matches, export_file)
        click.echo()
        click.echo(Fore.GREEN + f"  结果已导出到: {filepath}" + Style.RESET_ALL)

    if report_file:
        exporter = Exporter(export_dir=config.get("export_dir"))
        data_summary = compute_summary(entries)
        filepath = exporter.export_report_txt(data_summary, matches, report_file)
        click.echo()
        click.echo(Fore.GREEN + f"  报告已生成: {filepath}" + Style.RESET_ALL)


@cli.command()
@click.argument("paths", nargs=-1)
@click.option("-f", "--format", "log_format", default=None,
              help="日志格式 (combined/common)，默认: combined")
@click.option("--start", default=None, help="开始时间 (如: 2024-01-01 00:00:00)")
@click.option("--end", default=None, help="结束时间 (如: 2024-01-02 00:00:00)")
@click.option("-k", "--keyword", default=None, help="关键字过滤")
@click.option("-r", "--regex", default=None, help="正则表达式过滤")
@click.option("--field", default=None, help="指定过滤字段 (ip, path, user_agent 等)")
@click.option("-s", "--status", "status_codes", default=None,
              help="状态码过滤，逗号分隔 (如: 404,500)")
@click.option("--ip", "ips", default=None, help="IP过滤，逗号分隔")
@click.option("-n", "--limit", default=20, help="显示数量，默认: 20")
@click.option("--page", default=1, help="页码，默认: 1")
@click.option("--page-size", default=None, type=int, help="每页大小")
@click.option("--highlight", multiple=True, help="关键字高亮，可多次指定")
@click.option("-v", "--verbose", is_flag=True, help="显示详细信息")
@click.option("--summary/--no-summary", default=True, help="是否显示摘要")
@click.option("--export", "export_file", default=None, help="导出结果到CSV/TXT文件")
@click.option("--profile", default=None, help="使用配置档案")
@click.pass_context
def filter(ctx, paths, log_format, start, end, keyword, regex, field,
           status_codes, ips, limit, page, page_size, highlight, verbose,
           summary, export_file, profile):
    """按条件过滤日志，支持时间、关键字、正则、状态码、IP等过滤"""
    config = ctx.obj["config"]

    if profile:
        prof = config.load_profile(profile)
        if prof:
            if not paths and "paths" in prof:
                paths = tuple(prof["paths"])
            if not log_format and "format" in prof:
                log_format = prof["format"]
            if not start and "start" in prof:
                start = prof["start"]
            if not end and "end" in prof:
                end = prof["end"]
            if not keyword and "keyword" in prof:
                keyword = prof["keyword"]
        else:
            click.echo(Fore.YELLOW + f"警告: 配置档案 '{profile}' 不存在" + Style.RESET_ALL)

    log_format = log_format or config.get("default_format", "combined")
    page_size = page_size or config.get("page_size", 20)

    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    status_list = None
    if status_codes:
        status_list = [int(s.strip()) for s in status_codes.split(",") if s.strip()]

    ip_list = None
    if ips:
        ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()]

    highlight_list = list(highlight)
    if keyword and keyword not in highlight_list:
        highlight_list.append(keyword)

    entries = _load_entries(
        list(paths), log_format, start, end, keyword, regex, status_list, ip_list, field
    )

    if summary:
        data_summary = compute_summary(entries)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "  过滤结果摘要" + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo()
        click.echo(f"  匹配条目: {data_summary['total_requests']} 条")
        click.echo(f"  独立IP:   {data_summary['unique_ips']} 个")
        click.echo(f"  独立路径: {data_summary['unique_paths']} 个")
        click.echo(f"  总流量:   {_format_size(data_summary['total_bytes'])}")
        click.echo(f"  时间范围: {data_summary['time_range_start']} ~ "
                   f"{data_summary['time_range_end']}")
        click.echo()

    total = len(entries)
    total_pages = (total + page_size - 1) // page_size
    start_idx = (page - 1) * page_size
    end_idx = min(start_idx + page_size, total)
    page_entries = entries[start_idx:end_idx]

    click.echo(Fore.YELLOW + Style.BRIGHT + f"  日志条目 (第{page}页，共{total}条):" + Style.RESET_ALL)
    click.echo()

    for i, entry in enumerate(page_entries, start=start_idx + 1):
        _print_entry(entry, i, highlight_list, show_all=verbose)

    if total_pages > 1:
        click.echo()
        click.echo(f"  第 {page}/{total_pages} 页 | "
                   f"共 {total} 条 | 每页 {page_size} 条")

    if export_file:
        exporter = Exporter(export_dir=config.get("export_dir"))
        if export_file.endswith(".csv"):
            filepath = exporter.export_entries_csv(entries, export_file)
        else:
            filepath = exporter.export_entries_txt(entries, export_file)
        click.echo()
        click.echo(Fore.GREEN + f"  结果已导出到: {filepath}" + Style.RESET_ALL)


@cli.command()
@click.argument("paths", nargs=-1)
@click.option("-f", "--format", "log_format", default=None,
              help="日志格式 (combined/common)")
@click.option("--start", default=None, help="开始时间")
@click.option("--end", default=None, help="结束时间")
@click.option("-t", "--type", "stat_type", default="ip",
              type=click.Choice(["ip", "status", "path", "method"]),
              help="聚合类型: ip/status/path/method，默认: ip")
@click.option("-n", "--limit", default=20, help="显示TOP N，默认: 20")
@click.option("--min-count", default=1, help="最小请求数过滤")
@click.option("--freq", "high_freq", is_flag=True, help="检测高频请求IP")
@click.option("--threshold", default=100, help="高频请求阈值，默认: 100")
@click.option("--window", default=60, help="检测时间窗口(秒)，默认: 60")
@click.option("--export", "export_file", default=None, help="导出结果到CSV")
@click.option("--profile", default=None, help="使用配置档案")
@click.pass_context
def top(ctx, paths, log_format, start, end, stat_type, limit, min_count,
        high_freq, threshold, window, export_file, profile):
    """按IP、状态码、路径等聚合统计，显示TOP排名和高频请求"""
    config = ctx.obj["config"]

    if profile:
        prof = config.load_profile(profile)
        if prof:
            if not paths and "paths" in prof:
                paths = tuple(prof["paths"])
            if not log_format and "format" in prof:
                log_format = prof["format"]
            if not start and "start" in prof:
                start = prof["start"]
            if not end and "end" in prof:
                end = prof["end"]
        else:
            click.echo(Fore.YELLOW + f"警告: 配置档案 '{profile}' 不存在" + Style.RESET_ALL)

    log_format = log_format or config.get("default_format", "combined")

    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    entries = _load_entries(list(paths), log_format, start, end)

    if high_freq:
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "  高频请求IP检测" + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo()
        click.echo(f"  阈值: {threshold} 次/{window} 秒")
        click.echo()

        high_freq_ips = detect_high_frequency(entries, threshold=threshold,
                                              window_seconds=window)

        if not high_freq_ips:
            click.echo(Fore.GREEN + "  未检测到高频请求IP" + Style.RESET_ALL)
        else:
            click.echo(f"  检测到 {len(high_freq_ips)} 个高频请求IP:")
            click.echo()
            for i, hf in enumerate(high_freq_ips[:limit], 1):
                click.echo(f"  [{i}] {Fore.RED}{hf['ip']}{Style.RESET_ALL}")
                click.echo(f"       总请求数: {hf['request_count']}")
                click.echo(f"       峰值请求: {hf['peak_count']} 次")
                click.echo(f"       峰值时段: {hf['peak_start']} ~ {hf['peak_end']}")
                click.echo()
        return

    if stat_type == "ip":
        stats = aggregate_by_ip(entries)
        stats = [s for s in stats if s["count"] >= min_count]

        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + f"  TOP IP 统计 (共{len(stats)}个IP)" + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo()

        max_count = stats[0]["count"] if stats else 1

        for i, stat in enumerate(stats[:limit], 1):
            bar_len = int(stat["count"] / max_count * 30)
            bar = Fore.GREEN + "█" * bar_len + Style.RESET_ALL
            click.echo(f"  [{i:2d}] {stat['ip']:15s}  {stat['count']:6d} 次  {bar}")
            if stat["statuses"]:
                status_str = "  ".join(
                    f"{Fore.YELLOW if s >= 400 else ''}{s}:{c}{Style.RESET_ALL}"
                    for s, c in sorted(stat["statuses"].items())
                )
                click.echo(f"       状态码: {status_str}")
            click.echo()

    elif stat_type == "status":
        stats = aggregate_by_status(entries)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "  状态码统计" + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo()

        total = sum(s["count"] for s in stats)
        for i, stat in enumerate(stats, 1):
            status = stat["status"]
            count = stat["count"]
            pct = count / total * 100 if total > 0 else 0
            bar_len = int(pct / 100 * 40)
            if status >= 500:
                color = Fore.RED
            elif status >= 400:
                color = Fore.YELLOW
            elif status >= 300:
                color = Fore.CYAN
            else:
                color = Fore.GREEN
            bar = color + "█" * bar_len + Style.RESET_ALL
            click.echo(f"  {color}{status}{Style.RESET_ALL}: {count:6d} ({pct:5.1f}%)  {bar}")
            click.echo(f"       独立IP: {stat['unique_ips']} 个")
            click.echo()

    elif stat_type == "path":
        stats = aggregate_by_path(entries, limit=limit)
        stats = [s for s in stats if s["count"] >= min_count]

        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + f"  TOP 路径统计" + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
        click.echo()

        for i, stat in enumerate(stats[:limit], 1):
            path = stat["path"]
            if len(path) > 50:
                path = path[:47] + "..."
            click.echo(f"  [{i:2d}] {stat['count']:6d} 次  {path}")
            click.echo(f"       独立IP: {stat['unique_ips']} 个")
            click.echo()

    if export_file:
        exporter = Exporter(export_dir=config.get("export_dir"))
        if stat_type == "ip":
            filepath = exporter.export_top_ips_csv(stats, export_file)
        else:
            filename = f"top_{stat_type}.csv"
            filepath = os.path.join(config.get("export_dir"), export_file)
            import csv
            with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                if stat_type == "status":
                    writer.writerow(["状态码", "请求数", "独立IP数"])
                    for s in stats:
                        writer.writerow([s["status"], s["count"], s["unique_ips"]])
                elif stat_type == "path":
                    writer.writerow(["路径", "请求数", "独立IP数"])
                    for s in stats[:limit]:
                        writer.writerow([s["path"], s["count"], s["unique_ips"]])
        click.echo()
        click.echo(Fore.GREEN + f"  结果已导出到: {filepath}" + Style.RESET_ALL)


@cli.command()
@click.argument("ip")
@click.argument("paths", nargs=-1)
@click.option("-f", "--format", "log_format", default=None, help="日志格式")
@click.option("--start", default=None, help="开始时间")
@click.option("--end", default=None, help="结束时间")
@click.option("-n", "--limit", default=50, help="显示条目数限制")
@click.option("--page", default=1, help="页码")
@click.option("--page-size", default=None, type=int, help="每页大小")
@click.option("-k", "--highlight", multiple=True, help="关键字高亮")
@click.option("--export", "export_file", default=None, help="导出到CSV/TXT")
@click.option("--profile", default=None, help="使用配置档案")
@click.pass_context
def trace(ctx, ip, paths, log_format, start, end, limit, page, page_size,
          highlight, export_file, profile):
    """追踪单个IP的完整访问会话链路"""
    config = ctx.obj["config"]

    if profile:
        prof = config.load_profile(profile)
        if prof:
            if not paths and "paths" in prof:
                paths = tuple(prof["paths"])
            if not log_format and "format" in prof:
                log_format = prof["format"]
            if not start and "start" in prof:
                start = prof["start"]
            if not end and "end" in prof:
                end = prof["end"]
        else:
            click.echo(Fore.YELLOW + f"警告: 配置档案 '{profile}' 不存在" + Style.RESET_ALL)

    log_format = log_format or config.get("default_format", "combined")
    page_size = page_size or config.get("page_size", 20)

    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    entries = _load_entries(list(paths), log_format, start, end)
    session = get_session_trace(entries, ip)

    if not session:
        click.echo(Fore.YELLOW + f"未找到 IP {ip} 的任何访问记录" + Style.RESET_ALL)
        sys.exit(0)

    click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
    click.echo(Fore.CYAN + Style.BRIGHT + f"  会话追踪 - {ip}" + Style.RESET_ALL)
    click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
    click.echo()

    unique_paths = len(set(e.path for e in session))
    status_dist = {}
    for e in session:
        status_dist[e.status] = status_dist.get(e.status, 0) + 1

    first_time = session[0].timestamp.strftime("%Y-%m-%d %H:%M:%S") if session[0].timestamp else "N/A"
    last_time = session[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S") if session[-1].timestamp else "N/A"

    click.echo(f"  总请求数: {len(session)} 条")
    click.echo(f"  独立路径: {unique_paths} 个")
    click.echo(f"  首访时间: {first_time}")
    click.echo(f"  末访时间: {last_time}")
    click.echo(f"  状态码分布: {status_dist}")
    click.echo()

    total = len(session)
    start_idx = (page - 1) * page_size
    end_idx = min(start_idx + page_size, total)
    page_entries = session[start_idx:end_idx]

    click.echo(Fore.YELLOW + Style.BRIGHT + f"  访问链路 (第{page}页，共{total}条):" + Style.RESET_ALL)
    click.echo()

    for i, entry in enumerate(page_entries, start=start_idx + 1):
        ts = entry.timestamp.strftime("%H:%M:%S") if entry.timestamp else "??:??:??"
        status = str(entry.status)
        if entry.status >= 500:
            status_c = Fore.RED + status + Style.RESET_ALL
        elif entry.status >= 400:
            status_c = Fore.YELLOW + status + Style.RESET_ALL
        elif entry.status >= 300:
            status_c = Fore.CYAN + status + Style.RESET_ALL
        else:
            status_c = Fore.GREEN + status + Style.RESET_ALL

        path = entry.path
        if highlight:
            path = _highlight_keywords(path, list(highlight))

        click.echo(f"  [{i:3d}] {Fore.CYAN}{ts}{Style.RESET_ALL}  "
                   f"{entry.method:6s}  {status_c}  {path}")

    total_pages = (total + page_size - 1) // page_size
    if total_pages > 1:
        click.echo()
        click.echo(f"  第 {page}/{total_pages} 页 | 共 {total} 条")

    if export_file:
        exporter = Exporter(export_dir=config.get("export_dir"))
        if export_file.endswith(".csv"):
            filepath = exporter.export_entries_csv(session, export_file)
        else:
            filepath = exporter.export_entries_txt(session, export_file)
        click.echo()
        click.echo(Fore.GREEN + f"  结果已导出到: {filepath}" + Style.RESET_ALL)


@cli.command()
@click.argument("paths", nargs=-1)
@click.option("-f", "--format", "log_format", default=None, help="日志格式")
@click.option("--start", default=None, help="开始时间")
@click.option("--end", default=None, help="结束时间")
@click.option("-k", "--keyword", default=None, help="关键字过滤")
@click.option("-r", "--regex", default=None, help="正则过滤")
@click.option("-s", "--status", "status_codes", default=None, help="状态码过滤")
@click.option("--ip", "ips", default=None, help="IP过滤")
@click.option("--type", "export_type", default="csv",
              type=click.Choice(["csv", "txt", "json", "report"]),
              help="导出格式: csv/txt/json/report，默认: csv")
@click.option("-o", "--output", default=None, help="输出文件名")
@click.option("--output-dir", default=None, help="输出目录")
@click.option("--scan/--no-scan", default=False, help="是否包含异常扫描结果")
@click.option("--rules", "rules_file", default=None, help="异常规则配置文件路径")
@click.option("--no-default-rules", is_flag=True, help="不加载内置规则")
@click.option("--profile", default=None, help="使用配置档案")
@click.pass_context
def export(ctx, paths, log_format, start, end, keyword, regex, status_codes,
           ips, export_type, output, output_dir, scan, rules_file, no_default_rules, profile):
    """导出分析结果，支持CSV、文本、JSON和排查报告格式"""
    config = ctx.obj["config"]

    if profile:
        prof = config.load_profile(profile)
        if prof:
            if not paths and "paths" in prof:
                paths = tuple(prof["paths"])
            if not log_format and "format" in prof:
                log_format = prof["format"]
            if not start and "start" in prof:
                start = prof["start"]
            if not end and "end" in prof:
                end = prof["end"]
            if not rules_file and "rules_file" in prof:
                rules_file = prof["rules_file"]
        else:
            click.echo(Fore.YELLOW + f"警告: 配置档案 '{profile}' 不存在" + Style.RESET_ALL)

    log_format = log_format or config.get("default_format", "combined")
    export_dir = output_dir or config.get("export_dir")

    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    status_list = None
    if status_codes:
        status_list = [int(s.strip()) for s in status_codes.split(",") if s.strip()]

    ip_list = None
    if ips:
        ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()]

    entries = _load_entries(
        list(paths), log_format, start, end, keyword, regex, status_list, ip_list
    )

    exporter = Exporter(export_dir=export_dir)
    summary = compute_summary(entries)

    matches = None
    if scan:
        engine = RuleEngine()
        if not no_default_rules:
            engine.load_default_rules()
        if rules_file:
            engine.load_rules_file(rules_file)
        else:
            for rf in config.get("rules_files", []):
                engine.load_rules_file(rf)
        matches = engine.scan_entries(entries)

    if export_type == "csv":
        filepath = exporter.export_entries_csv(entries, output)
    elif export_type == "txt":
        filepath = exporter.export_entries_txt(entries, output)
    elif export_type == "json":
        filepath = exporter.export_summary_json(summary, output)
    elif export_type == "report":
        filepath = exporter.export_report_txt(summary, matches, output)

    click.echo(Fore.GREEN + f"导出成功!" + Style.RESET_ALL)
    click.echo(f"  文件: {filepath}")
    click.echo(f"  条目数: {len(entries)}")
    if scan and matches:
        click.echo(f"  告警数: {len(matches)}")


def _print_scan_summary(matches: List[RuleMatch]):
    """在终端输出扫描结果的分组摘要"""
    if not matches:
        click.echo(Fore.GREEN + "  未检测到异常访问" + Style.RESET_ALL)
        return

    grouped = group_matches(matches)
    total = len(matches)

    click.echo(Fore.YELLOW + Style.BRIGHT + "  > 攻击类型统计:" + Style.RESET_ALL)
    attack_sorted = sorted(grouped["by_attack"].items(),
                           key=lambda x: len(x[1]), reverse=True)
    for i, (attack_name, attack_matches) in enumerate(attack_sorted[:10], 1):
        disp = get_disposition(attack_name)
        uniq_ips = len(set(m.entry.ip for m in attack_matches))
        max_sev = max((m.rule.severity for m in attack_matches),
                      key=lambda s: {"critical": 4, "high": 3, "medium": 2,
                                     "low": 1, "warning": 0}.get(s, 0))
        sev_color = SEVERITY_COLORS.get(max_sev, "")
        sev_tag = SEVERITY_TAGS.get(max_sev, "")
        click.echo(f"    [{i:2d}] {sev_color}{sev_tag}{Style.RESET_ALL} "
                   f"{attack_name:28s} {len(attack_matches):>4d}次  "
                   f"{uniq_ips:>2d}IP  {disp['threat']}")
    click.echo()

    click.echo(Fore.YELLOW + Style.BRIGHT + "  > 攻击源IP (TOP 8):" + Style.RESET_ALL)
    ip_sorted = sorted(grouped["by_ip"].items(),
                       key=lambda x: len(x[1]), reverse=True)
    for i, (ip, ip_matches) in enumerate(ip_sorted[:8], 1):
        sevs = defaultdict(int)
        attacks = set()
        for m in ip_matches:
            sevs[m.rule.severity] += 1
            attacks.add(m.rule.name)
        max_sev = max(sevs.keys(),
                      key=lambda s: {"critical": 4, "high": 3, "medium": 2,
                                     "low": 1, "warning": 0}.get(s, 0))
        sev_color = SEVERITY_COLORS.get(max_sev, "")
        sev_str = " ".join(f"{k}:{v}" for k, v in sorted(sevs.items()))
        click.echo(f"    [{i:2d}] {sev_color}{ip:18s}{Style.RESET_ALL}  "
                   f"{len(ip_matches):>3d}条  {sev_str}")
        click.echo(f"         攻击: {', '.join(sorted(attacks)[:4])}")
    click.echo()

    click.echo(Fore.YELLOW + Style.BRIGHT + "  > 受影响路径 (TOP 8):" + Style.RESET_ALL)
    path_sorted = sorted(grouped["by_path"].items(),
                         key=lambda x: len(x[1]), reverse=True)
    for i, (path, path_matches) in enumerate(path_sorted[:8], 1):
        uniq_ips = len(set(m.entry.ip for m in path_matches))
        max_sev = max((m.rule.severity for m in path_matches),
                      key=lambda s: {"critical": 4, "high": 3, "medium": 2,
                                     "low": 1, "warning": 0}.get(s, 0))
        sev_color = SEVERITY_COLORS.get(max_sev, "")
        sev_tag = SEVERITY_TAGS.get(max_sev, "")
        display_path = path if len(path) <= 48 else path[:45] + "..."
        click.echo(f"    [{i:2d}] {sev_color}{sev_tag}{Style.RESET_ALL} "
                   f"{len(path_matches):>3d}次 {uniq_ips:>2d}IP  {display_path}")
    click.echo()

    critical_count = sum(1 for m in matches if m.rule.severity == "critical")
    high_count = sum(1 for m in matches if m.rule.severity == "high")
    risk = risk_level(total, critical_count, high_count)
    risk_color = Fore.RED + Style.BRIGHT if risk in ("极高", "高") else (
        Fore.YELLOW if risk == "中" else Fore.GREEN)
    click.echo(f"  {risk_color}综合风险等级: {risk}{Style.RESET_ALL}")

    if critical_count > 0 or high_count > 0:
        click.echo()
        click.echo(Fore.RED + Style.BRIGHT + "  ! 处置建议 (高危告警):" + Style.RESET_ALL)
        attack_displayed = set()
        for attack_name, _ in attack_sorted:
            if attack_name in attack_displayed:
                continue
            disp = get_disposition(attack_name)
            top_matches = [m for m in matches if m.rule.name == attack_name]
            max_sev = max((m.rule.severity for m in top_matches),
                          key=lambda s: {"critical": 4, "high": 3, "medium": 2,
                                         "low": 1, "warning": 0}.get(s, 0))
            if max_sev not in ("critical", "high"):
                continue
            attack_displayed.add(attack_name)
            sev_color = SEVERITY_COLORS.get(max_sev, "")
            click.echo(f"    {sev_color}* {disp['threat']}{Style.RESET_ALL}")
            for action in disp["actions"][:3]:
                click.echo(f"      · {action}")
            if len(attack_displayed) >= 3:
                break


@cli.command()
@click.argument("paths", nargs=-1)
@click.option("-f", "--format", "log_format", default=None, help="日志格式")
@click.option("-r", "--rules", "rules_file", default=None, help="异常规则配置文件")
@click.option("--no-default-rules", is_flag=True, help="不加载内置规则")
@click.option("--severity", default=None,
              help="只显示指定严重级别的告警 (critical/high/medium/low)")
@click.option("--ip", "watch_ips", default=None, help="只监控指定IP，逗号分隔")
@click.option("--high-only", is_flag=True, help="只显示高危及以上告警 (critical/high)")
@click.option("--interval", default=1.0, type=float, help="文件读取间隔(秒)，默认: 1.0")
@click.option("--threshold", default=30, type=int,
              help="高频请求告警阈值(次/分钟)，默认: 30")
@click.option("--no-stats", is_flag=True, help="不显示实时统计栏")
@click.option("--profile", default=None, help="使用配置档案")
@click.pass_context
def watch(ctx, paths, log_format, rules_file, no_default_rules, severity,
          watch_ips, high_only, interval, threshold, no_stats, profile):
    """实时监控日志文件，滚动显示异常告警和高频请求"""
    config = ctx.obj["config"]

    if profile:
        prof = config.load_profile(profile)
        if prof:
            if not paths and "paths" in prof:
                paths = tuple(prof["paths"])
            if not log_format and "format" in prof:
                log_format = prof["format"]
            if not rules_file and "rules_file" in prof:
                rules_file = prof["rules_file"]
        else:
            click.echo(Fore.YELLOW + f"警告: 配置档案 '{profile}' 不存在" + Style.RESET_ALL)

    log_format = log_format or config.get("default_format", "combined")
    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    files = resolve_paths(list(paths))
    if not files:
        click.echo(Fore.RED + "未找到任何日志文件" + Style.RESET_ALL)
        sys.exit(1)

    engine = RuleEngine()
    if not no_default_rules:
        engine.load_default_rules()
    if rules_file:
        engine.load_rules_file(rules_file)
    else:
        for rf in config.get("rules_files", []):
            engine.load_rules_file(rf)

    ip_filter = None
    if watch_ips:
        ip_filter = [ip.strip() for ip in watch_ips.split(",") if ip.strip()]

    parser = LogParser(log_format=log_format)
    file_positions = {}
    for fp in files:
        try:
            file_positions[fp] = os.path.getsize(fp)
        except OSError:
            file_positions[fp] = 0

    ip_window: Dict[str, deque] = defaultdict(lambda: deque(maxlen=threshold * 2))
    total_alerts = 0
    total_requests = 0
    alerted_ips = set()
    start_time = datetime.now()

    click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
    click.echo(Fore.CYAN + Style.BRIGHT + "  日志实时监控模式 - Logalyzer Watch" + Style.RESET_ALL)
    click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
    click.echo()
    click.echo(f"  监控文件: {len(files)} 个")
    for f in files:
        click.echo(f"    - {f}")
    click.echo(f"  加载规则: {len(engine.rules)} 条")
    click.echo(f"  扫描间隔: {interval}s")
    click.echo(f"  高频阈值: {threshold}次/分钟")
    if high_only:
        click.echo(f"  过滤模式: 仅高危及以上")
    if severity:
        click.echo(f"  过滤级别: {severity}")
    if ip_filter:
        click.echo(f"  监控IP: {', '.join(ip_filter)}")
    click.echo()
    click.echo(Fore.YELLOW + "  按 Ctrl+C 退出监控" + Style.RESET_ALL)
    click.echo()

    try:
        while True:
            batch_matches: List[RuleMatch] = []

            for fp in files:
                try:
                    current_size = os.path.getsize(fp)
                except OSError:
                    continue

                last_pos = file_positions.get(fp, 0)
                if current_size < last_pos:
                    file_positions[fp] = 0
                    last_pos = 0

                if current_size > last_pos:
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            f.seek(last_pos)
                            new_lines = f.readlines()
                        file_positions[fp] = current_size

                        for line in new_lines:
                            entry = parser.parse_line(line, os.path.basename(fp))
                            if not entry:
                                continue

                            total_requests += 1

                            if ip_filter and entry.ip not in ip_filter:
                                continue

                            if entry.timestamp:
                                ip_window[entry.ip].append(entry.timestamp.timestamp())

                            if threshold > 0 and entry.ip not in alerted_ips:
                                recent = [t for t in ip_window[entry.ip]
                                          if time.time() - t <= 60]
                                if len(recent) >= threshold:
                                    alerted_ips.add(entry.ip)
                                    ts = entry.timestamp.strftime("%H:%M:%S") if entry.timestamp else "??:??:??"
                                    click.echo(
                                        Fore.RED + Style.BRIGHT +
                                        f"  ! [{ts}] [高频] IP {entry.ip} 触发高频请求 "
                                        f"({len(recent)}次/分钟)" +
                                        Style.RESET_ALL
                                    )

                            matches = engine.scan_entry(entry)
                            for m in matches:
                                if high_only and m.rule.severity not in ("critical", "high"):
                                    continue
                                if severity and m.rule.severity != severity:
                                    continue
                                batch_matches.append(m)
                                total_alerts += 1

                                sev_color = SEVERITY_COLORS.get(m.rule.severity, "")
                                sev_tag = SEVERITY_TAGS.get(m.rule.severity, "")
                                ts = m.entry.timestamp.strftime("%H:%M:%S") if m.entry.timestamp else "??:??:??"
                                disp = get_disposition(m.rule.name)
                                click.echo(
                                    f"  {sev_color}{sev_tag}{Style.RESET_ALL} "
                                    f"{Fore.CYAN}[{ts}]{Style.RESET_ALL} "
                                    f"{m.entry.ip:15s}  {m.entry.method:4s} "
                                    f"{m.entry.status:>3d}  {m.rule.name}"
                                )
                                click.echo(
                                    f"       {m.entry.path[:70]}"
                                )
                                if m.rule.severity in ("critical", "high"):
                                    click.echo(
                                        f"       {Fore.MAGENTA}威胁:{Style.RESET_ALL} "
                                        f"{disp['threat']} | "
                                        f"{Fore.MAGENTA}建议:{Style.RESET_ALL} "
                                        f"{disp['actions'][0]}"
                                    )
                                click.echo()

                    except (IOError, OSError):
                        continue

            if not no_stats and (total_requests % 50 == 0 or total_alerts % 5 == 0) and total_requests > 0:
                elapsed = (datetime.now() - start_time).total_seconds()
                click.echo(
                    Fore.CYAN + Style.DIM +
                    f"  ── 统计: 已处理 {total_requests} 条 | "
                    f"告警 {total_alerts} 条 | "
                    f"运行 {int(elapsed)}s ──" +
                    Style.RESET_ALL
                )

            time.sleep(interval)

    except KeyboardInterrupt:
        click.echo()
        click.echo()
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "  监控结束" + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
        elapsed = (datetime.now() - start_time).total_seconds()
        click.echo()
        click.echo(f"  运行时长: {int(elapsed)} 秒")
        click.echo(f"  处理请求: {total_requests} 条")
        click.echo(f"  触发告警: {total_alerts} 条")
        if alerted_ips:
            click.echo(f"  高频IP:   {', '.join(sorted(alerted_ips))}")
        click.echo()


@cli.group()
@click.pass_context
def config(ctx):
    """管理工具配置，保存常用参数和配置文件"""
    pass


@config.command("show")
@click.pass_context
def config_show(ctx):
    """显示当前配置"""
    config = ctx.obj["config"]
    cfg = config.get_config()

    click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
    click.echo(Fore.CYAN + Style.BRIGHT + "  当前配置" + Style.RESET_ALL)
    click.echo(Fore.CYAN + Style.BRIGHT + "=" * 60 + Style.RESET_ALL)
    click.echo()

    click.echo(f"  配置文件: {config.config_file}")
    click.echo(f"  配置目录: {config.config_dir}")
    click.echo(f"  导出目录: {cfg.get('export_dir', 'N/A')}")
    click.echo(f"  默认格式: {cfg.get('default_format', 'N/A')}")
    click.echo(f"  页面大小: {cfg.get('page_size', 'N/A')}")
    click.echo()

    log_paths = cfg.get("default_log_paths", [])
    click.echo(f"  默认日志路径 ({len(log_paths)}):")
    if log_paths:
        for p in log_paths:
            click.echo(f"    - {p}")
    else:
        click.echo("    (无)")
    click.echo()

    rules_files = cfg.get("rules_files", [])
    click.echo(f"  规则文件 ({len(rules_files)}):")
    if rules_files:
        for r in rules_files:
            click.echo(f"    - {r}")
    else:
        click.echo("    (无)")
    click.echo()

    highlight_kws = cfg.get("highlight_keywords", [])
    click.echo(f"  高亮关键字 ({len(highlight_kws)}):")
    if highlight_kws:
        for kw in highlight_kws:
            click.echo(f"    - {kw}")
    else:
        click.echo("    (无)")
    click.echo()

    profiles = config.list_profiles()
    click.echo(f"  保存的配置档案 ({len(profiles)}):")
    if profiles:
        for p in profiles:
            click.echo(f"    - {p}")
    else:
        click.echo("    (无)")


@config.command("set")
@click.option("--format", "log_format", default=None, help="默认日志格式")
@click.option("--page-size", default=None, type=int, help="默认页面大小")
@click.option("--export-dir", default=None, help="默认导出目录")
@click.pass_context
def config_set(ctx, log_format, page_size, export_dir):
    """设置配置项"""
    config = ctx.obj["config"]
    updated = []

    if log_format:
        config.set("default_format", log_format)
        updated.append(f"default_format = {log_format}")
    if page_size:
        config.set("page_size", page_size)
        updated.append(f"page_size = {page_size}")
    if export_dir:
        config.set("export_dir", export_dir)
        updated.append(f"export_dir = {export_dir}")

    if updated:
        config.save()
        click.echo(Fore.GREEN + "配置已更新:" + Style.RESET_ALL)
        for u in updated:
            click.echo(f"  {u}")
    else:
        click.echo(Fore.YELLOW + "未指定任何配置项" + Style.RESET_ALL)


@config.command("add-path")
@click.argument("path")
@click.pass_context
def config_add_path(ctx, path):
    """添加默认日志路径"""
    config = ctx.obj["config"]
    config.add_log_path(path)
    config.save()
    click.echo(Fore.GREEN + f"已添加日志路径: {path}" + Style.RESET_ALL)


@config.command("remove-path")
@click.argument("path")
@click.pass_context
def config_remove_path(ctx, path):
    """移除默认日志路径"""
    config = ctx.obj["config"]
    if config.remove_log_path(path):
        config.save()
        click.echo(Fore.GREEN + f"已移除日志路径: {path}" + Style.RESET_ALL)
    else:
        click.echo(Fore.YELLOW + f"路径不存在: {path}" + Style.RESET_ALL)


@config.command("add-rules")
@click.argument("filepath")
@click.pass_context
def config_add_rules(ctx, filepath):
    """添加规则文件"""
    config = ctx.obj["config"]
    config.add_rules_file(filepath)
    config.save()
    click.echo(Fore.GREEN + f"已添加规则文件: {filepath}" + Style.RESET_ALL)


@config.command("remove-rules")
@click.argument("filepath")
@click.pass_context
def config_remove_rules(ctx, filepath):
    """移除规则文件"""
    config = ctx.obj["config"]
    if config.remove_rules_file(filepath):
        config.save()
        click.echo(Fore.GREEN + f"已移除规则文件: {filepath}" + Style.RESET_ALL)
    else:
        click.echo(Fore.YELLOW + f"规则文件不存在: {filepath}" + Style.RESET_ALL)


@config.command("save-profile")
@click.argument("name")
@click.option("--paths", default=None, help="日志路径，逗号分隔")
@click.option("--format", "log_format", default=None, help="日志格式")
@click.option("--start", default=None, help="默认开始时间")
@click.option("--end", default=None, help="默认结束时间")
@click.option("--rules", "rules_file", default=None, help="异常规则配置文件路径")
@click.option("--keyword", default=None, help="默认关键字过滤")
@click.option("--ip", default=None, help="默认IP过滤，逗号分隔")
@click.option("--status", default=None, help="默认状态码过滤，逗号分隔")
@click.pass_context
def config_save_profile(ctx, name, paths, log_format, start, end, rules_file, keyword, ip, status):
    """保存常用参数为配置档案"""
    config = ctx.obj["config"]
    profile = {}
    if paths:
        profile["paths"] = [p.strip() for p in paths.split(",")]
    if log_format:
        profile["format"] = log_format
    if start:
        profile["start"] = start
    if end:
        profile["end"] = end
    if rules_file:
        profile["rules_file"] = rules_file
    if keyword:
        profile["keyword"] = keyword
    if ip:
        profile["ips"] = [x.strip() for x in ip.split(",")]
    if status:
        profile["status_codes"] = status

    if not profile:
        click.echo(Fore.YELLOW + "请至少指定一个参数" + Style.RESET_ALL)
        return

    if config.save_profile(name, profile):
        click.echo(Fore.GREEN + f"配置档案 '{name}' 已保存" + Style.RESET_ALL)
    else:
        click.echo(Fore.RED + "保存失败" + Style.RESET_ALL)


@config.command("load-profile")
@click.argument("name")
@click.pass_context
def config_load_profile(ctx, name):
    """加载配置档案"""
    config = ctx.obj["config"]
    profile = config.load_profile(name)
    if profile:
        click.echo(Fore.GREEN + f"配置档案 '{name}':" + Style.RESET_ALL)
        for k, v in profile.items():
            click.echo(f"  {k}: {v}")
    else:
        click.echo(Fore.RED + f"配置档案 '{name}' 不存在" + Style.RESET_ALL)


@config.command("list-profiles")
@click.pass_context
def config_list_profiles(ctx):
    """列出所有配置档案"""
    config = ctx.obj["config"]
    profiles = config.list_profiles()
    if profiles:
        click.echo(Fore.CYAN + f"配置档案 ({len(profiles)}):" + Style.RESET_ALL)
        for p in profiles:
            click.echo(f"  - {p}")
    else:
        click.echo(Fore.YELLOW + "暂无配置档案" + Style.RESET_ALL)


@config.command("delete-profile")
@click.argument("name")
@click.pass_context
def config_delete_profile(ctx, name):
    """删除配置档案"""
    config = ctx.obj["config"]
    if config.delete_profile(name):
        click.echo(Fore.GREEN + f"配置档案 '{name}' 已删除" + Style.RESET_ALL)
    else:
        click.echo(Fore.YELLOW + f"配置档案 '{name}' 不存在" + Style.RESET_ALL)


def main():
    cli()


if __name__ == "__main__":
    main()
