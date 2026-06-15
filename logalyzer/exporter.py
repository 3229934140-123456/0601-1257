import os
import csv
import json
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Optional, Tuple
from .parser import LogEntry
from .rules import RuleMatch


ATTACK_DISPOSITION = {
    "sql_injection_attempt": {
        "threat": "SQL注入攻击",
        "impact": "可能导致数据库泄露、数据篡改或权限绕过",
        "actions": [
            "【紧急】立即封禁源IP，检查WAF规则是否生效",
            "审计相关数据表，确认是否存在数据泄露或篡改",
            "检查Web应用输入验证和参数化查询实现",
            "保留完整攻击日志作为取证证据",
        ],
    },
    "xss_attempt": {
        "threat": "跨站脚本攻击(XSS)",
        "impact": "可能导致用户会话劫持、Cookie窃取或页面篡改",
        "actions": [
            "封禁源IP，加强前端输入过滤和输出编码",
            "检查CSP(内容安全策略)配置是否完善",
            "排查是否存在已植入的恶意脚本",
            "通知用户修改密码并重新登录",
        ],
    },
    "path_traversal": {
        "threat": "目录遍历/路径穿越攻击",
        "impact": "可能导致敏感文件泄露、系统配置暴露",
        "actions": [
            "封禁源IP，检查Web服务器目录访问限制",
            "核查.git、.svn、.env等敏感文件是否可被访问",
            "检查应用文件包含和路径拼接逻辑",
            "确认是否有敏感文件已被下载",
        ],
    },
    "scanner_detected": {
        "threat": "自动化安全扫描",
        "impact": "表明攻击者正在进行信息收集，可能为后续攻击做准备",
        "actions": [
            "封禁扫描源IP，配置扫描检测规则",
            "检查是否存在已被扫描器发现的脆弱点",
            "评估WAF和IDS规则覆盖率",
            "关注该IP后续是否有进一步攻击行为",
        ],
    },
    "suspicious_user_agent": {
        "threat": "可疑User-Agent(扫描工具特征)",
        "impact": "可能为自动化扫描或爬虫行为",
        "actions": [
            "记录并监控该UA后续行为",
            "配置UA黑名单或行为限速",
            "检查robots.txt和爬虫限制策略",
        ],
    },
    "brute_force_login": {
        "threat": "登录接口暴力破解",
        "impact": "可能导致账号被盗、权限提升",
        "actions": [
            "【紧急】封禁源IP，启用登录失败次数限制",
            "核查相关账号是否存在弱口令",
            "强制相关用户修改密码并开启双因素认证",
            "检查登录日志确认是否有成功登录记录",
        ],
    },
    "file_upload_attempt": {
        "threat": "恶意文件上传尝试",
        "impact": "可能导致WebShell植入、服务器远程代码执行",
        "actions": [
            "【紧急】封禁源IP，检查上传目录是否有可疑文件",
            "核查文件上传白名单和类型校验机制",
            "扫描上传目录是否存在WebShell",
            "限制上传目录脚本执行权限",
        ],
    },
    "webshell_detection": {
        "threat": "WebShell访问/植入",
        "impact": "服务器已被入侵，攻击者可远程执行命令",
        "actions": [
            "【高危】立即隔离受影响服务器，断开网络连接",
            "全面排查Web目录，清除所有可疑文件",
            "核查系统账号、计划任务、启动项是否被篡改",
            "进行完整入侵响应和取证分析",
            "所有关联密码强制重置",
        ],
    },
    "command_injection": {
        "threat": "命令注入攻击",
        "impact": "可能导致服务器被远程控制、数据泄露",
        "actions": [
            "【紧急】封禁源IP，检查应用命令执行逻辑",
            "核查是否有可疑系统命令被执行",
            "审计系统日志和bash历史记录",
            "加固参数过滤，禁止直接拼接系统命令",
        ],
    },
    "sensitive_path_access": {
        "threat": "敏感路径探测",
        "impact": "攻击者尝试收集系统信息、探测脆弱点",
        "actions": [
            "封禁源IP，配置敏感路径访问告警",
            "检查敏感文件权限和访问控制",
            "隐藏服务器版本信息和错误详情",
        ],
    },
    "server_error_5xx": {
        "threat": "服务器错误(5xx)",
        "impact": "可能由攻击Payload触发，也可能是应用Bug",
        "actions": [
            "检查5xx错误是否由特定请求参数触发",
            "关联分析错误前后的访问日志",
            "修复应用异常处理逻辑，避免敏感信息泄露",
        ],
    },
    "client_error_4xx": {
        "threat": "客户端错误(4xx)",
        "impact": "大量4xx可能为探测扫描或配置问题",
        "actions": [
            "如为特定IP集中触发，结合其他规则判断是否为攻击",
            "检查是否存在失效链接或配置错误",
        ],
    },
    "error_5xx": {
        "threat": "服务器内部错误",
        "impact": "应用异常或攻击触发",
        "actions": [
            "排查错误根因，修复应用问题",
            "检查是否与攻击Payload相关",
        ],
    },
    "error_4xx_high": {
        "threat": "客户端错误告警",
        "impact": "访问受限或资源不存在",
        "actions": [
            "结合上下文判断为正常访问还是攻击探测",
        ],
    },
}

DEFAULT_DISPOSITION = {
    "threat": "异常访问行为",
    "impact": "需要进一步分析确认风险等级",
    "actions": [
        "监控该IP后续行为",
        "结合上下文和其他规则综合研判",
        "必要时封禁可疑IP",
    ],
}


def get_disposition(rule_name: str) -> Dict:
    return ATTACK_DISPOSITION.get(rule_name, DEFAULT_DISPOSITION)


def group_matches(matches: List[RuleMatch]) -> Dict:
    by_attack: Dict[str, List[RuleMatch]] = defaultdict(list)
    by_ip: Dict[str, List[RuleMatch]] = defaultdict(list)
    by_path: Dict[str, List[RuleMatch]] = defaultdict(list)

    for m in matches:
        by_attack[m.rule.name].append(m)
        by_ip[m.entry.ip].append(m)
        path = m.entry.path.split("?")[0] if "?" in m.entry.path else m.entry.path
        by_path[path].append(m)

    return {
        "by_attack": dict(by_attack),
        "by_ip": dict(by_ip),
        "by_path": dict(by_path),
    }


def risk_level(total_matches: int, critical_count: int, high_count: int) -> str:
    if critical_count > 0:
        return "极高"
    elif high_count >= 5 or total_matches >= 50:
        return "高"
    elif high_count >= 1 or total_matches >= 10:
        return "中"
    else:
        return "低"


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

        critical_count = 0
        high_count = 0
        if matches:
            critical_count = sum(1 for m in matches if m.rule.severity == "critical")
            high_count = sum(1 for m in matches if m.rule.severity == "high")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("                    日志安全分析排查报告\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if matches:
                risk = risk_level(len(matches), critical_count, high_count)
                f.write(f"风险等级: {risk}\n")
            f.write(f"分析范围: {summary.get('time_range_start', 'N/A')} ~ "
                    f"{summary.get('time_range_end', 'N/A')}\n\n")

            f.write("-" * 70 + "\n")
            f.write("【一】流量概览\n")
            f.write("-" * 70 + "\n")
            f.write(f"  总请求数:     {summary.get('total_requests', 0):>8,d}\n")
            f.write(f"  独立IP数:     {summary.get('unique_ips', 0):>8,d}\n")
            f.write(f"  独立路径数:   {summary.get('unique_paths', 0):>8,d}\n")
            f.write(f"  总流量:       {_format_size(summary.get('total_bytes', 0)):>10s}\n")
            f.write(f"  平均请求大小: {_format_size(summary.get('avg_request_size', 0)):>10s}\n\n")

            f.write("-" * 70 + "\n")
            f.write("【二】状态码分布\n")
            f.write("-" * 70 + "\n")
            status_dist = summary.get("status_distribution", {})
            if status_dist:
                max_val = max(status_dist.values())
                for status in sorted(status_dist.keys()):
                    count = status_dist[status]
                    pct = count / sum(status_dist.values()) * 100 if status_dist else 0
                    bar = "█" * int(count / max_val * 30)
                    f.write(f"  {status}: {count:>6d} ({pct:5.1f}%)  {bar}\n")
            f.write("\n")

            f.write("-" * 70 + "\n")
            f.write("【三】HTTP方法分布\n")
            f.write("-" * 70 + "\n")
            method_dist = summary.get("method_distribution", {})
            for method in sorted(method_dist.keys()):
                count = method_dist[method]
                f.write(f"  {method:6s}: {count:>6,d}\n")
            f.write("\n")

            if matches:
                grouped = group_matches(matches)
                total = len(matches)
                unique_ips = len(grouped["by_ip"])

                f.write("-" * 70 + "\n")
                f.write(f"【四】威胁检测总览 (共 {total} 条告警, 涉及 {unique_ips} 个IP)\n")
                f.write("-" * 70 + "\n\n")

                by_severity: Dict[str, int] = defaultdict(int)
                for m in matches:
                    by_severity[m.rule.severity] += 1

                f.write("  ▶ 按严重级别统计:\n")
                for sev in ["critical", "high", "medium", "low", "warning"]:
                    count = by_severity.get(sev, 0)
                    if count > 0:
                        tag = {"critical": "[严重]", "high": "[高危]", "medium": "[中危]",
                               "low": "[低危]", "warning": "[警告]"}.get(sev, "")
                        f.write(f"    {tag}{sev:10s}: {count:>4d} 条\n")
                f.write("\n")

                f.write("  ▶ 按攻击类型统计 (TOP 15):\n")
                attack_sorted = sorted(grouped["by_attack"].items(),
                                       key=lambda x: len(x[1]), reverse=True)
                for i, (attack_name, attack_matches) in enumerate(attack_sorted[:15], 1):
                    disp = get_disposition(attack_name)
                    uniq_ips = len(set(m.entry.ip for m in attack_matches))
                    f.write(f"    [{i:2d}] {attack_name:30s} {len(attack_matches):>4d}次 "
                            f"({uniq_ips:>2d}个IP) - {disp['threat']}\n")
                f.write("\n")

                f.write("-" * 70 + "\n")
                f.write("【五】攻击源IP分析 (TOP 15)\n")
                f.write("-" * 70 + "\n\n")

                ip_sorted = sorted(grouped["by_ip"].items(),
                                   key=lambda x: len(x[1]), reverse=True)
                for i, (ip, ip_matches) in enumerate(ip_sorted[:15], 1):
                    sevs = defaultdict(int)
                    attacks = set()
                    paths = set()
                    for m in ip_matches:
                        sevs[m.rule.severity] += 1
                        attacks.add(m.rule.name)
                        p = m.entry.path.split("?")[0]
                        paths.add(p)

                    sev_str = " ".join(f"{k}:{v}" for k, v in sorted(sevs.items()))
                    f.write(f"  [{i:2d}] {ip:18s}  总告警: {len(ip_matches):>3d}\n")
                    f.write(f"       级别分布: {sev_str}\n")
                    f.write(f"       攻击类型: {', '.join(sorted(attacks)[:5])}\n")
                    f.write(f"       影响路径: {len(paths)} 个\n")

                    first_ts = min((m.entry.timestamp for m in ip_matches if m.entry.timestamp),
                                   default=None)
                    last_ts = max((m.entry.timestamp for m in ip_matches if m.entry.timestamp),
                                  default=None)
                    if first_ts and last_ts:
                        f.write(f"       活跃时段: {first_ts.strftime('%H:%M:%S')} ~ "
                                f"{last_ts.strftime('%H:%M:%S')}\n")
                    f.write("\n")

                f.write("-" * 70 + "\n")
                f.write("【六】受影响路径分析 (TOP 15)\n")
                f.write("-" * 70 + "\n\n")

                path_sorted = sorted(grouped["by_path"].items(),
                                     key=lambda x: len(x[1]), reverse=True)
                for i, (path, path_matches) in enumerate(path_sorted[:15], 1):
                    uniq_ips = len(set(m.entry.ip for m in path_matches))
                    attack_types = set(m.rule.name for m in path_matches)
                    max_sev = max((m.rule.severity for m in path_matches),
                                  key=lambda s: {"critical": 4, "high": 3, "medium": 2,
                                                 "low": 1, "warning": 0}.get(s, 0))
                    sev_tag = {"critical": "[严重]", "high": "[高危]", "medium": "[中危]",
                               "low": "[低危]", "warning": "[警告]"}.get(max_sev, "")
                    display_path = path if len(path) <= 55 else path[:52] + "..."
                    f.write(f"  [{i:2d}] {sev_tag} {display_path}\n")
                    f.write(f"       命中 {len(path_matches):>3d} 次 | "
                            f"{uniq_ips:>2d} 个源IP | "
                            f"攻击类型: {', '.join(sorted(attack_types)[:3])}\n\n")

                f.write("-" * 70 + "\n")
                f.write("【七】高危告警详情\n")
                f.write("-" * 70 + "\n\n")

                critical_matches = [m for m in matches
                                    if m.rule.severity in ("critical", "high")]
                critical_matches.sort(key=lambda m: (
                    {"critical": 0, "high": 1}.get(m.rule.severity, 99),
                    -(m.entry.timestamp.timestamp() if m.entry.timestamp else 0)
                ))

                if critical_matches:
                    for i, m in enumerate(critical_matches[:30], 1):
                        ts = m.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if m.entry.timestamp else "N/A"
                        sev_tag = "[严重]" if m.rule.severity == "critical" else "[高危]"
                        disp = get_disposition(m.rule.name)
                        f.write(f"  [{i:2d}] {sev_tag} {m.rule.name} - {disp['threat']}\n")
                        f.write(f"       时间:   {ts}\n")
                        f.write(f"       源IP:   {m.entry.ip}\n")
                        f.write(f"       方法:   {m.entry.method}  状态码: {m.entry.status}\n")
                        f.write(f"       路径:   {m.entry.path}\n")
                        f.write(f"       详情:   {m.detail}\n")
                        f.write(f"       影响:   {disp['impact']}\n")
                        f.write(f"       UA:     {m.entry.user_agent[:80]}\n\n")
                else:
                    f.write("  (无高危告警)\n\n")

                f.write("-" * 70 + "\n")
                f.write("【八】处置建议 (可直接复制到工单)\n")
                f.write("-" * 70 + "\n\n")

                f.write("═══════════════════════════════════════════════════════════════\n")
                f.write("  [工单处置建议]\n")
                f.write("═══════════════════════════════════════════════════════════════\n\n")

                attack_handled = set()
                for attack_name, attack_matches in attack_sorted:
                    if attack_name in attack_handled:
                        continue
                    attack_handled.add(attack_name)

                    disp = get_disposition(attack_name)
                    uniq_ips = sorted(set(m.entry.ip for m in attack_matches))
                    affected_paths = sorted(set(
                        m.entry.path.split("?")[0] for m in attack_matches
                    ))

                    f.write(f"  ■ 威胁: {disp['threat']} ({attack_name})\n")
                    f.write(f"    风险影响: {disp['impact']}\n")
                    f.write(f"    涉及IP ({len(uniq_ips)}个): {', '.join(uniq_ips[:5])}\n")
                    if len(uniq_ips) > 5:
                        f.write(f"                  等{len(uniq_ips)}个IP\n")
                    f.write(f"    影响路径 ({len(affected_paths)}个):\n")
                    for p in affected_paths[:3]:
                        f.write(f"      - {p}\n")
                    if len(affected_paths) > 3:
                        f.write(f"      ... 等{len(affected_paths)}个路径\n")
                    f.write(f"    处置步骤:\n")
                    for j, action in enumerate(disp["actions"], 1):
                        f.write(f"      {j}. {action}\n")
                    f.write("\n")

                if ip_sorted:
                    f.write("  ■ 建议封禁IP清单:\n")
                    for ip, ip_matches in ip_sorted[:10]:
                        sevs = defaultdict(int)
                        for m in ip_matches:
                            sevs[m.rule.severity] += 1
                        sev_str = ", ".join(f"{k}×{v}" for k, v in sorted(sevs.items()))
                        f.write(f"    - {ip:18s}  ({len(ip_matches)}条告警, {sev_str})\n")
                    f.write("\n")

                f.write("  ■ 通用建议:\n")
                f.write("    1. 以上IP建议立即加入防火墙/WAF黑名单\n")
                f.write("    2. 检查受影响系统是否已被成功入侵\n")
                f.write("    3. 保留所有相关日志作为取证材料\n")
                f.write("    4. 跟进漏洞修复和安全加固工作\n")
                f.write("\n═══════════════════════════════════════════════════════════════\n\n")

            f.write("=" * 70 + "\n")
            f.write("                      报告结束\n")
            f.write("=" * 70 + "\n")

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

