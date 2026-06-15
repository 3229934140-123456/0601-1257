import sys
import os
import re
import csv
import json
import time
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import List, Optional, Dict

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


def _apply_profile(config, profile_name, paths=None, log_format=None, start=None,
                   end=None, rules_file=None, keyword=None, ips=None,
                   status_codes=None, regex=None):
    """从配置档案加载参数，命令行显式指定的参数优先级更高"""
    prof = config.load_profile(profile_name)
    if not prof:
        click.echo(Fore.YELLOW + f"警告: 配置档案 '{profile_name}' 不存在" + Style.RESET_ALL)
        return paths, log_format, start, end, rules_file, keyword, ips, status_codes, regex

    if not paths and "paths" in prof:
        paths = tuple(prof["paths"]) if isinstance(prof["paths"], list) else (prof["paths"],)
    if not log_format and "format" in prof:
        log_format = prof["format"]
    if not start and "start" in prof:
        start = prof["start"]
    if not end and "end" in prof:
        end = prof["end"]
    if not rules_file and "rules_file" in prof:
        rules_file = prof["rules_file"]
    if not keyword and "keyword" in prof:
        keyword = prof["keyword"]
    if not ips and "ips" in prof:
        v = prof["ips"]
        ips = ",".join(v) if isinstance(v, list) else v
    if not status_codes and "status_codes" in prof:
        v = prof["status_codes"]
        status_codes = ",".join(str(x) for x in v) if isinstance(v, list) else str(v)
    if not regex and "regex" in prof:
        regex = prof["regex"]

    return paths, log_format, start, end, rules_file, keyword, ips, status_codes, regex


def _parse_status_list(status_codes):
    if not status_codes:
        return None
    return [int(s.strip()) for s in str(status_codes).split(",") if s.strip()]


def _parse_ip_list(ips):
    if not ips:
        return None
    return [ip.strip() for ip in str(ips).split(",") if ip.strip()]


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

    p_keyword = None
    p_ips = None
    p_status = None

    if profile:
        paths, log_format, start, end, rules_file, p_keyword, p_ips, p_status, _ = _apply_profile(
            config, profile, paths, log_format, start, end, rules_file)

    log_format = log_format or config.get("default_format", "combined")
    page_size = page_size or config.get("page_size", 20)

    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    status_list = _parse_status_list(p_status)
    ip_list = _parse_ip_list(p_ips)

    entries = _load_entries(list(paths), log_format, start, end,
                            keyword=p_keyword, status_codes=status_list, ips=ip_list)

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
        paths, log_format, start, end, _, keyword, ips, status_codes, regex = _apply_profile(
            config, profile, paths, log_format, start, end,
            keyword=keyword, ips=ips, status_codes=status_codes, regex=regex)

    log_format = log_format or config.get("default_format", "combined")
    page_size = page_size or config.get("page_size", 20)

    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    status_list = _parse_status_list(status_codes)
    ip_list = _parse_ip_list(ips)

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

    p_keyword = None
    p_ips = None
    p_status = None

    if profile:
        paths, log_format, start, end, _, p_keyword, p_ips, p_status, _ = _apply_profile(
            config, profile, paths, log_format, start, end)

    log_format = log_format or config.get("default_format", "combined")

    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    status_list = _parse_status_list(p_status)
    ip_list = _parse_ip_list(p_ips)

    entries = _load_entries(list(paths), log_format, start, end, keyword=p_keyword,
                            status_codes=status_list, ips=ip_list)

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
        paths, log_format, start, end, _, _, _, _, _ = _apply_profile(
            config, profile, paths, log_format, start, end)

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
        paths, log_format, start, end, rules_file, keyword, ips, status_codes, regex = _apply_profile(
            config, profile, paths, log_format, start, end, rules_file,
            keyword=keyword, ips=ips, status_codes=status_codes, regex=regex)

    log_format = log_format or config.get("default_format", "combined")
    export_dir = output_dir or config.get("export_dir")

    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)

    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    status_list = _parse_status_list(status_codes)
    ip_list = _parse_ip_list(ips)

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
        paths, log_format, _, _, rules_file, _, prof_ips, _, _ = _apply_profile(
            config, profile, paths, log_format, rules_file=rules_file)
        if not watch_ips and prof_ips:
            watch_ips = prof_ips

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

    ALERT_MERGE_WINDOW = 30

    ip_alert_buffer: Dict[str, List[RuleMatch]] = defaultdict(list)
    ip_last_flush: Dict[str, float] = {}
    all_alerts: List[RuleMatch] = []

    try:
        while True:
            batch_matches: List[RuleMatch] = []
            now_ts = time.time()

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
                                all_alerts.append(m)
                                ip = m.entry.ip

                                if m.rule.severity in ("critical", "high"):
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
                                    click.echo(f"       {m.entry.path[:70]}")
                                    click.echo(
                                        f"       {Fore.MAGENTA}威胁:{Style.RESET_ALL} "
                                        f"{disp['threat']} | "
                                        f"{Fore.MAGENTA}建议:{Style.RESET_ALL} "
                                        f"{disp['actions'][0]}"
                                    )
                                    click.echo()
                                else:
                                    ip_alert_buffer[ip].append(m)
                                    ip_last_flush[ip] = now_ts

                    except (IOError, OSError):
                        continue

            for ip in list(ip_alert_buffer.keys()):
                if not ip_alert_buffer[ip]:
                    continue
                last_t = ip_last_flush.get(ip, 0)
                if now_ts - last_t >= ALERT_MERGE_WINDOW or len(ip_alert_buffer[ip]) >= 5:
                    buffered = ip_alert_buffer[ip]
                    click.echo(
                        Fore.YELLOW + f"  [摘要] IP {ip} "
                        f"最近{ALERT_MERGE_WINDOW}s内 {len(buffered)} 条中低危告警:" +
                        Style.RESET_ALL
                    )
                    attack_counts = defaultdict(int)
                    for m in buffered:
                        attack_counts[m.rule.name] += 1
                    for name, cnt in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
                        click.echo(f"       {name}: {cnt}次")
                    click.echo()
                    ip_alert_buffer[ip] = []

            if not no_stats and (total_requests % 50 == 0 or total_alerts % 5 == 0) and total_requests > 0:
                elapsed = (datetime.now() - start_time).total_seconds()
                click.echo(
                    Fore.CYAN + Style.DIM +
                    f"  -- 统计: 已处理 {total_requests} 条 | "
                    f"告警 {total_alerts} 条 | "
                    f"运行 {int(elapsed)}s --" +
                    Style.RESET_ALL
                )

            time.sleep(interval)

    except KeyboardInterrupt:
        for ip in ip_alert_buffer:
            if ip_alert_buffer[ip]:
                buffered = ip_alert_buffer[ip]
                click.echo(
                    Fore.YELLOW + f"  [摘要] IP {ip} "
                    f"剩余 {len(buffered)} 条中低危告警:" +
                    Style.RESET_ALL
                )
                attack_counts = defaultdict(int)
                for m in buffered:
                    attack_counts[m.rule.name] += 1
                for name, cnt in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
                    click.echo(f"       {name}: {cnt}次")
                click.echo()

        click.echo()
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "  监控结束 - 告警小结" + Style.RESET_ALL)
        click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
        elapsed = (datetime.now() - start_time).total_seconds()
        click.echo()
        click.echo(f"  运行时长: {int(elapsed)} 秒")
        click.echo(f"  处理请求: {total_requests} 条")
        click.echo(f"  触发告警: {total_alerts} 条")
        if alerted_ips:
            click.echo(f"  高频IP:   {', '.join(sorted(alerted_ips))}")
        click.echo()

        if all_alerts:
            sevs = defaultdict(int)
            attacks = defaultdict(int)
            alert_ips_map = defaultdict(int)
            for m in all_alerts:
                sevs[m.rule.severity] += 1
                attacks[m.rule.name] += 1
                alert_ips_map[m.entry.ip] += 1

            click.echo(Fore.YELLOW + "  告警级别分布:" + Style.RESET_ALL)
            for sev in ["critical", "high", "medium", "low"]:
                if sevs[sev] > 0:
                    color = SEVERITY_COLORS.get(sev, "")
                    tag = SEVERITY_TAGS.get(sev, "")
                    click.echo(f"    {color}{tag}{Style.RESET_ALL} {sevs[sev]}条")

            click.echo()
            click.echo(Fore.YELLOW + "  TOP攻击类型:" + Style.RESET_ALL)
            for name, cnt in sorted(attacks.items(), key=lambda x: x[1], reverse=True)[:5]:
                click.echo(f"    {name}: {cnt}次")

            click.echo()
            click.echo(Fore.YELLOW + "  TOP告警源IP:" + Style.RESET_ALL)
            for ip, cnt in sorted(alert_ips_map.items(), key=lambda x: x[1], reverse=True)[:8]:
                click.echo(f"    {ip:18s} {cnt}条")

            critical_m = [m for m in all_alerts if m.rule.severity == "critical"]
            high_m = [m for m in all_alerts if m.rule.severity == "high"]
            if critical_m or high_m:
                click.echo()
                click.echo(Fore.RED + Style.BRIGHT + "  高危处置建议:" + Style.RESET_ALL)
                shown = set()
                for m in (critical_m + high_m):
                    if m.rule.name in shown:
                        continue
                    shown.add(m.rule.name)
                    disp = get_disposition(m.rule.name)
                    click.echo(f"    * {disp['threat']}")
                    click.echo(f"      {disp['actions'][0]}")
                    if len(shown) >= 3:
                        break
        click.echo()


@cli.command()
@click.argument("paths", nargs=-1)
@click.option("-f", "--format", "log_format", default=None, help="日志格式")
@click.option("--start", default=None, help="开始时间")
@click.option("--end", default=None, help="结束时间")
@click.option("-r", "--rules", "rules_file", default=None, help="异常规则文件")
@click.option("--no-default-rules", is_flag=True, help="不加载内置规则")
@click.option("-n", "--name", "incident_name", default=None, help="事件名称(默认自动生成)")
@click.option("-o", "--output-dir", default=None, help="事件包输出目录")
@click.option("--profile", default=None, help="使用配置档案")
@click.pass_context
def incident(ctx, paths, log_format, start, end, rules_file, no_default_rules,
             incident_name, output_dir, profile):
    """将扫描结果打包为可复盘的事件目录，方便交接班"""
    import shutil
    config = ctx.obj["config"]

    if profile:
        paths, log_format, start, end, rules_file, _, _, _, _ = _apply_profile(
            config, profile, paths, log_format, start, end, rules_file)

    log_format = log_format or config.get("default_format", "combined")
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

    matches = engine.scan_entries(entries)
    data_summary = compute_summary(entries)

    now = datetime.now()
    if not incident_name:
        incident_name = f"INC-{now.strftime('%Y%m%d-%H%M%S')}"

    inc_dir = os.path.join(output_dir or config.get("export_dir") or ".", incident_name)
    os.makedirs(inc_dir, exist_ok=True)

    # summary.txt
    grouped = group_matches(matches)
    critical_count = sum(1 for m in matches if m.rule.severity == "critical")
    high_count = sum(1 for m in matches if m.rule.severity == "high")
    risk = risk_level(len(matches), critical_count, high_count)

    with open(os.path.join(inc_dir, "summary.txt"), "w", encoding="utf-8") as f:
        f.write(f"事件名称: {incident_name}\n")
        f.write(f"生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"风险等级: {risk}\n")
        f.write(f"日志条目: {data_summary['total_requests']}\n")
        f.write(f"告警总数: {len(matches)}\n")
        f.write(f"涉及IP:   {data_summary['unique_ips']}\n")
        f.write(f"时间范围: {data_summary['time_range_start']} ~ {data_summary['time_range_end']}\n\n")

        f.write("=" * 60 + "\n")
        f.write("攻击类型统计\n")
        f.write("=" * 60 + "\n")
        for attack_name, attack_matches in sorted(grouped["by_attack"].items(),
                                                   key=lambda x: len(x[1]), reverse=True):
            disp = get_disposition(attack_name)
            uniq_ips = sorted(set(m.entry.ip for m in attack_matches))
            f.write(f"\n  [{attack_name}] {len(attack_matches)}次\n")
            f.write(f"    威胁: {disp['threat']}\n")
            f.write(f"    影响: {disp['impact']}\n")
            f.write(f"    源IP: {', '.join(uniq_ips[:10])}\n")
            for a in disp["actions"][:3]:
                f.write(f"    * {a}\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("攻击源IP分析\n")
        f.write("=" * 60 + "\n")
        for ip, ip_matches in sorted(grouped["by_ip"].items(),
                                      key=lambda x: len(x[1]), reverse=True):
            attacks = sorted(set(m.rule.name for m in ip_matches))
            sevs = defaultdict(int)
            for m in ip_matches:
                sevs[m.rule.severity] += 1
            f.write(f"\n  {ip} - {len(ip_matches)}条告警\n")
            f.write(f"    级别: {dict(sevs)}\n")
            f.write(f"    攻击: {', '.join(attacks[:6])}\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("受影响路径\n")
        f.write("=" * 60 + "\n")
        for path, path_matches in sorted(grouped["by_path"].items(),
                                          key=lambda x: len(x[1]), reverse=True)[:20]:
            uniq_ips = sorted(set(m.entry.ip for m in path_matches))
            f.write(f"  {path} - {len(path_matches)}次 | IP: {', '.join(uniq_ips[:5])}\n")

    # disposition.txt
    with open(os.path.join(inc_dir, "disposition.txt"), "w", encoding="utf-8") as f:
        f.write(f"事件: {incident_name} | 风险: {risk}\n")
        f.write("=" * 60 + "\n\n")
        displayed = set()
        for attack_name, attack_matches in sorted(grouped["by_attack"].items(),
                                                   key=lambda x: len(x[1]), reverse=True):
            if attack_name in displayed:
                continue
            displayed.add(attack_name)
            disp = get_disposition(attack_name)
            uniq_ips = sorted(set(m.entry.ip for m in attack_matches))
            f.write(f"【{disp['threat']}】\n")
            f.write(f"  风险影响: {disp['impact']}\n")
            f.write(f"  涉及IP ({len(uniq_ips)}): {', '.join(uniq_ips[:10])}\n")
            f.write(f"  处置步骤:\n")
            for i, a in enumerate(disp["actions"], 1):
                f.write(f"    {i}. {a}\n")
            f.write("\n")

        ban_ips = sorted(grouped["by_ip"].keys(),
                         key=lambda ip: len(grouped["by_ip"][ip]), reverse=True)
        if ban_ips:
            f.write("建议封禁IP:\n")
            for ip in ban_ips:
                cnt = len(grouped["by_ip"][ip])
                f.write(f"  - {ip} ({cnt}条告警)\n")

    # alerts.csv
    with open(os.path.join(inc_dir, "alerts.csv"), "w", newline="",
              encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["严重级别", "规则名称", "时间", "源IP", "方法", "状态码",
                         "路径", "详情", "威胁描述"])
        for m in matches:
            disp = get_disposition(m.rule.name)
            ts = m.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if m.entry.timestamp else ""
            writer.writerow([
                m.rule.severity, m.rule.name, ts, m.entry.ip,
                m.entry.method, m.entry.status, m.entry.path,
                m.detail, disp["threat"]
            ])

    # raw_logs.log
    with open(os.path.join(inc_dir, "raw_logs.log"), "w", encoding="utf-8") as f:
        alert_ips = set(m.entry.ip for m in matches)
        alert_paths = set(m.entry.path for m in matches)
        for e in entries:
            if e.ip in alert_ips or e.path in alert_paths:
                f.write(e.raw + "\n")

    # metadata.json
    meta = {
        "incident_name": incident_name,
        "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "risk_level": risk,
        "log_sources": list(paths) if paths else [],
        "time_range": {
            "start": data_summary["time_range_start"],
            "end": data_summary["time_range_end"],
        },
        "stats": {
            "total_entries": data_summary["total_requests"],
            "total_alerts": len(matches),
            "critical": critical_count,
            "high": high_count,
            "unique_ips": data_summary["unique_ips"],
        },
        "files": ["summary.txt", "disposition.txt", "alerts.csv", "raw_logs.log", "metadata.json"],
    }
    with open(os.path.join(inc_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    click.echo(Fore.GREEN + f"事件包已生成: {inc_dir}" + Style.RESET_ALL)
    click.echo(f"  风险等级: {risk}")
    click.echo(f"  告警总数: {len(matches)}")
    click.echo(f"  包含文件:")
    click.echo(f"    summary.txt      - 事件摘要与攻击分析")
    click.echo(f"    disposition.txt  - 处置建议(可复制到工单)")
    click.echo(f"    alerts.csv       - 告警明细表")
    click.echo(f"    raw_logs.log     - 关联原始日志片段")
    click.echo(f"    metadata.json    - 元数据")


@cli.command()
@click.argument("paths", nargs=-1)
@click.option("-f", "--format", "log_format", default=None, help="日志格式")
@click.option("--start", default=None, help="当前时段开始时间")
@click.option("--end", default=None, help="当前时段结束时间")
@click.option("--baseline-start", default=None, help="基线时段开始时间")
@click.option("--baseline-end", default=None, help="基线时段结束时间")
@click.option("--shift", default="1d",
              help="时间偏移(如1d=1天,2h=2小时),自动推算基线时段")
@click.option("-r", "--rules", "rules_file", default=None, help="异常规则文件")
@click.option("--no-default-rules", is_flag=True, help="不加载内置规则")
@click.option("-n", "--limit", default=10, help="每类显示TOP N")
@click.option("--profile", default=None, help="使用配置档案")
@click.pass_context
def baseline(ctx, paths, log_format, start, end, baseline_start, baseline_end,
             shift, rules_file, no_default_rules, limit, profile):
    """基线对比: 比较两个时段的日志差异，发现新增威胁和异常增长"""
    config = ctx.obj["config"]

    if profile:
        paths, log_format, start, end, rules_file, _, _, _, _ = _apply_profile(
            config, profile, paths, log_format, start, end, rules_file)

    log_format = log_format or config.get("default_format", "combined")
    default_paths = config.get("default_log_paths", [])
    if not paths and default_paths:
        paths = tuple(default_paths)
    if not paths:
        click.echo(Fore.RED + "请指定日志文件或目录路径" + Style.RESET_ALL)
        sys.exit(1)

    if not baseline_start or not baseline_end:
        bl_start, bl_end = _shift_time(start, end, shift)
        if not bl_start or not bl_end:
            click.echo(Fore.RED + "请指定 --start/--end 或 --baseline-start/--baseline-end" + Style.RESET_ALL)
            sys.exit(1)
        baseline_start = bl_start
        baseline_end = bl_end

    current_entries = _load_entries(list(paths), log_format, start, end)
    baseline_entries = _load_entries(list(paths), log_format, baseline_start, baseline_end)

    if not current_entries and not baseline_entries:
        click.echo(Fore.RED + "两个时段均无日志数据" + Style.RESET_ALL)
        sys.exit(1)

    click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
    click.echo(Fore.CYAN + Style.BRIGHT + "  基线对比分析" + Style.RESET_ALL)
    click.echo(Fore.CYAN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
    click.echo()
    click.echo(f"  当前时段: {start or 'N/A'} ~ {end or 'N/A'}  ({len(current_entries)}条)")
    click.echo(f"  基线时段: {baseline_start} ~ {baseline_end}  ({len(baseline_entries)}条)")
    click.echo()

    cur_ips = defaultdict(int)
    cur_paths = defaultdict(int)
    cur_status = defaultdict(int)
    cur_path_by_ip = defaultdict(set)

    for e in current_entries:
        cur_ips[e.ip] += 1
        cur_paths[e.path] += 1
        cur_status[e.status] += 1
        cur_path_by_ip[e.ip].add(e.path)

    bl_ips = defaultdict(int)
    bl_paths = defaultdict(int)
    bl_status = defaultdict(int)
    bl_path_by_ip = defaultdict(set)

    for e in baseline_entries:
        bl_ips[e.ip] += 1
        bl_paths[e.path] += 1
        bl_status[e.status] += 1
        bl_path_by_ip[e.ip].add(e.path)

    # 1. 新增IP
    new_ips = set(cur_ips.keys()) - set(bl_ips.keys())
    if new_ips:
        click.echo(Fore.RED + Style.BRIGHT + "  > 新增IP (基线中未出现):" + Style.RESET_ALL)
        sorted_new = sorted(new_ips, key=lambda ip: cur_ips[ip], reverse=True)[:limit]
        for ip in sorted_new:
            click.echo(f"    {ip:18s} {cur_ips[ip]:>5d}次  "
                       f"路径数: {len(cur_path_by_ip[ip])}")
        click.echo()

    # 2. 异常增长IP
    growth_ips = []
    all_ips = set(cur_ips.keys()) & set(bl_ips.keys())
    for ip in all_ips:
        if bl_ips[ip] == 0:
            continue
        ratio = cur_ips[ip] / bl_ips[ip]
        if ratio >= 2.0 and cur_ips[ip] >= 5:
            growth_ips.append((ip, cur_ips[ip], bl_ips[ip], ratio))
    growth_ips.sort(key=lambda x: x[3], reverse=True)

    if growth_ips:
        click.echo(Fore.YELLOW + Style.BRIGHT + "  > 异常增长IP (同比>=2倍):" + Style.RESET_ALL)
        for ip, cur, bl, ratio in growth_ips[:limit]:
            click.echo(f"    {ip:18s} {bl:>4d} -> {cur:>4d}  "
                       f"{Fore.RED}{ratio:.1f}x{Style.RESET_ALL}")
        click.echo()

    # 3. 新增路径
    new_paths = set(cur_paths.keys()) - set(bl_paths.keys())
    if new_paths:
        click.echo(Fore.RED + Style.BRIGHT + "  > 新增路径 (基线中未出现):" + Style.RESET_ALL)
        sorted_np = sorted(new_paths, key=lambda p: cur_paths[p], reverse=True)[:limit]
        for path in sorted_np:
            p = path if len(path) <= 55 else path[:52] + "..."
            click.echo(f"    {cur_paths[path]:>4d}次  {p}")
        click.echo()

    # 4. 高危新增路径(用规则扫描)
    if new_paths:
        engine = RuleEngine()
        if not no_default_rules:
            engine.load_default_rules()
        if rules_file:
            engine.load_rules_file(rules_file)

        new_path_entries = [e for e in current_entries if e.path in new_paths]
        if new_path_entries:
            new_matches = engine.scan_entries(new_path_entries)
            high_new = [m for m in new_matches if m.rule.severity in ("critical", "high")]
            if high_new:
                click.echo(Fore.RED + Style.BRIGHT + "  > 高危新增路径 (命中规则):" + Style.RESET_ALL)
                seen = set()
                for m in high_new:
                    key = (m.entry.path, m.rule.name)
                    if key in seen:
                        continue
                    seen.add(key)
                    sev_color = SEVERITY_COLORS.get(m.rule.severity, "")
                    sev_tag = SEVERITY_TAGS.get(m.rule.severity, "")
                    click.echo(f"    {sev_color}{sev_tag}{Style.RESET_ALL} "
                               f"{m.rule.name}  {m.entry.path[:50]}")
                click.echo()

    # 5. 状态码变化
    click.echo(Fore.YELLOW + Style.BRIGHT + "  > 状态码分布对比:" + Style.RESET_ALL)
    all_status = sorted(set(list(cur_status.keys()) + list(bl_status.keys())))
    for s in all_status:
        c = cur_status.get(s, 0)
        b = bl_status.get(s, 0)
        if s >= 500:
            color = Fore.RED
        elif s >= 400:
            color = Fore.YELLOW
        else:
            color = Fore.GREEN
        diff = c - b
        diff_str = f"{Fore.RED}+{diff}" if diff > 0 else (
            f"{Fore.GREEN}{diff}" if diff < 0 else f"  0")
        if b > 0:
            pct = (c - b) / b * 100
            pct_str = f" ({pct:+.0f}%)" if abs(pct) >= 10 else ""
        else:
            pct_str = " (NEW)" if c > 0 else ""
        click.echo(f"    {color}{s}{Style.RESET_ALL}: "
                   f"基线 {b:>5d} -> 当前 {c:>5d}  {diff_str}{pct_str}{Style.RESET_ALL}")
    click.echo()

    # 6. 总体摘要
    total_delta = len(current_entries) - len(baseline_entries)
    delta_color = Fore.RED if total_delta > 0 else (Fore.GREEN if total_delta < 0 else "")
    click.echo(Fore.CYAN + Style.BRIGHT + "  总体摘要:" + Style.RESET_ALL)
    click.echo(f"    请求数变化: {delta_color}{len(baseline_entries)} -> "
               f"{len(current_entries)} ({total_delta:+d}){Style.RESET_ALL}")
    click.echo(f"    新增IP:     {Fore.RED}{len(new_ips)}{Style.RESET_ALL}  "
               f"增长IP: {Fore.YELLOW}{len(growth_ips)}{Style.RESET_ALL}  "
               f"新增路径: {Fore.RED}{len(new_paths)}{Style.RESET_ALL}")


def _shift_time(start, end, shift_str):
    """根据偏移量推算基线时段"""
    if not start or not end:
        return None, None

    from logalyzer.parser import _parse_datetime
    start_dt = _parse_datetime(start)
    end_dt = _parse_datetime(end)
    if not start_dt or not end_dt:
        return None, None

    delta = _parse_shift(shift_str)
    if delta is None:
        return None, None

    bl_start_dt = start_dt - delta
    bl_end_dt = end_dt - delta

    fmt = "%Y-%m-%d %H:%M:%S" if " " in start else "%Y-%m-%d"
    return bl_start_dt.strftime(fmt), bl_end_dt.strftime(fmt)


def _parse_shift(shift_str):
    """解析时间偏移字符串(如1d,2h,30m)"""
    from datetime import timedelta
    m = re.match(r'^(\d+)([dhm])$', shift_str.lower())
    if not m:
        return None
    val = int(m.group(1))
    unit = m.group(2)
    if unit == 'd':
        return timedelta(days=val)
    elif unit == 'h':
        return timedelta(hours=val)
    elif unit == 'm':
        return timedelta(minutes=val)
    return None


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
