import re
import os
import yaml
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from .parser import LogEntry


@dataclass
class Rule:
    name: str
    description: str
    severity: str = "warning"
    category: str = "general"
    enabled: bool = True
    type: str = "regex"
    pattern: str = ""
    target_field: Optional[str] = None
    status_codes: List[int] = field(default_factory=list)
    ip_blacklist: List[str] = field(default_factory=list)
    path_patterns: List[str] = field(default_factory=list)
    threshold: int = 0
    _compiled_patterns: List = field(default_factory=list)

    def compile(self):
        if self.pattern:
            self._compiled_patterns.append(re.compile(self.pattern, re.IGNORECASE))
        for p in self.path_patterns:
            self._compiled_patterns.append(re.compile(p, re.IGNORECASE))

    def match(self, entry: LogEntry) -> Tuple[bool, str]:
        if not self.enabled:
            return False, ""

        if self.type == "regex":
            return self._match_regex(entry)
        elif self.type == "status_code":
            return self._match_status(entry)
        elif self.type == "ip_blacklist":
            return self._match_ip(entry)
        elif self.type == "path_injection":
            return self._match_path_injection(entry)
        elif self.type == "sql_injection":
            return self._match_sql_injection(entry)
        elif self.type == "xss":
            return self._match_xss(entry)
        elif self.type == "scanner":
            return self._match_scanner(entry)

        return False, ""

    def _match_regex(self, entry: LogEntry) -> Tuple[bool, str]:
        if self.target_field:
            text = entry.get(self.target_field)
            for pattern in self._compiled_patterns:
                if pattern.search(text):
                    return True, f"Field '{self.target_field}' matches pattern '{pattern.pattern}'"
        else:
            for pattern in self._compiled_patterns:
                if pattern.search(entry.raw):
                    return True, f"Matches pattern '{pattern.pattern}'"
        return False, ""

    def _match_status(self, entry: LogEntry) -> Tuple[bool, str]:
        if entry.status in self.status_codes:
            return True, f"Status code {entry.status} is in watchlist"
        return False, ""

    def _match_ip(self, entry: LogEntry) -> Tuple[bool, str]:
        if entry.ip in self.ip_blacklist:
            return True, f"IP {entry.ip} is in blacklist"
        return False, ""

    def _match_path_injection(self, entry: LogEntry) -> Tuple[bool, str]:
        path = entry.path
        patterns = [
            r"\.\./", r"\.\.\\",
            r"/etc/passwd", r"c:\\windows",
            r"\.git/", r"\.svn/",
            r"proc/self/environ",
        ]
        for p in patterns:
            if re.search(p, path, re.IGNORECASE):
                return True, f"Path injection pattern detected: {p}"
        return False, ""

    def _match_sql_injection(self, entry: LogEntry) -> Tuple[bool, str]:
        path = entry.path + " " + entry.raw
        patterns = [
            r"['\"].*OR.*['\"]1['\"]=.*['\"]1",
            r"UNION.*SELECT",
            r"INSERT.*INTO",
            r"DELETE.*FROM",
            r"DROP.*TABLE",
            r"--.*$",
            r";.*(SELECT|INSERT|UPDATE|DELETE|DROP)",
        ]
        for p in patterns:
            if re.search(p, path, re.IGNORECASE):
                return True, f"SQL injection pattern detected: {p}"
        return False, ""

    def _match_xss(self, entry: LogEntry) -> Tuple[bool, str]:
        path = entry.path + " " + entry.raw
        patterns = [
            r"<script.*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
            r"eval\s*\(",
        ]
        for p in patterns:
            if re.search(p, path, re.IGNORECASE):
                return True, f"XSS pattern detected: {p}"
        return False, ""

    def _match_scanner(self, entry: LogEntry) -> Tuple[bool, str]:
        ua = entry.user_agent.lower()
        scanner_signatures = [
            "sqlmap", "nikto", "nmap", "nessus", "acunetix",
            "burp", "dirbuster", "gobuster", "wfuzz", "masscan",
            "python-requests", "curl/", "wget/", "scanner",
        ]
        for sig in scanner_signatures:
            if sig in ua:
                return True, f"Scanner signature detected in User-Agent: {sig}"
        return False, ""


@dataclass
class RuleMatch:
    rule: Rule
    entry: LogEntry
    detail: str


class RuleEngine:
    def __init__(self):
        self.rules: List[Rule] = []

    def load_rules_file(self, filepath: str) -> int:
        if not os.path.exists(filepath):
            return 0
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data or "rules" not in data:
            return 0
        count = 0
        for rule_data in data["rules"]:
            rule = Rule(
                name=rule_data.get("name", "unnamed"),
                description=rule_data.get("description", ""),
                severity=rule_data.get("severity", "warning"),
                category=rule_data.get("category", "general"),
                enabled=rule_data.get("enabled", True),
                type=rule_data.get("type", "regex"),
                pattern=rule_data.get("pattern", ""),
                target_field=rule_data.get("field"),
                status_codes=rule_data.get("status_codes", []),
                ip_blacklist=rule_data.get("ip_blacklist", []),
                path_patterns=rule_data.get("path_patterns", []),
                threshold=rule_data.get("threshold", 0),
            )
            rule.compile()
            self.rules.append(rule)
            count += 1
        return count

    def load_default_rules(self) -> int:
        builtin_rules = [
            Rule(
                name="sql_injection_attempt",
                description="检测SQL注入尝试",
                severity="critical",
                category="injection",
                type="sql_injection",
            ),
            Rule(
                name="xss_attempt",
                description="检测XSS攻击尝试",
                severity="high",
                category="injection",
                type="xss",
            ),
            Rule(
                name="path_traversal",
                description="检测路径遍历攻击",
                severity="high",
                category="injection",
                type="path_injection",
            ),
            Rule(
                name="scanner_detected",
                description="检测扫描器访问",
                severity="medium",
                category="recon",
                type="scanner",
            ),
            Rule(
                name="error_4xx_high",
                description="4xx错误状态码",
                severity="low",
                category="status",
                type="status_code",
                status_codes=[400, 401, 403, 404, 405, 429],
            ),
            Rule(
                name="error_5xx",
                description="5xx服务器错误",
                severity="medium",
                category="status",
                type="status_code",
                status_codes=[500, 502, 503, 504],
            ),
        ]
        for rule in builtin_rules:
            rule.compile()
            self.rules.append(rule)
        return len(builtin_rules)

    def scan_entry(self, entry: LogEntry) -> List[RuleMatch]:
        matches = []
        for rule in self.rules:
            matched, detail = rule.match(entry)
            if matched:
                matches.append(RuleMatch(rule=rule, entry=entry, detail=detail))
        return matches

    def scan_entries(self, entries: List[LogEntry]) -> List[RuleMatch]:
        all_matches = []
        for entry in entries:
            all_matches.extend(self.scan_entry(entry))
        return all_matches

    def get_rules_summary(self) -> Dict:
        summary = {
            "total": len(self.rules),
            "enabled": sum(1 for r in self.rules if r.enabled),
            "by_severity": {},
            "by_category": {},
        }
        for rule in self.rules:
            if not rule.enabled:
                continue
            summary["by_severity"][rule.severity] = summary["by_severity"].get(rule.severity, 0) + 1
            summary["by_category"][rule.category] = summary["by_category"].get(rule.category, 0) + 1
        return summary

    def match_summary(self, matches: List[RuleMatch]) -> Dict:
        summary = {
            "total_matches": len(matches),
            "unique_ips": len(set(m.entry.ip for m in matches)),
            "by_rule": {},
            "by_severity": {},
            "by_category": {},
        }
        for match in matches:
            rule = match.rule
            summary["by_rule"][rule.name] = summary["by_rule"].get(rule.name, 0) + 1
            summary["by_severity"][rule.severity] = summary["by_severity"].get(rule.severity, 0) + 1
            summary["by_category"][rule.category] = summary["by_category"].get(rule.category, 0) + 1
        return summary
