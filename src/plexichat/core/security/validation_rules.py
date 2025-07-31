import re

SQL_INJECTION_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE)\b)",
    r"(--|#|/\*|\*/)",
    r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
    r"(\bUNION\s+SELECT\b)",
    r"(\b(EXEC|EXECUTE)\s*\()",
    r"(\bxp_cmdshell\b)",
    r"(\bsp_executesql\b)",
    r"(\bINTO\s+OUTFILE\b)",
    r"(\bLOAD_FILE\b)"
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"vbscript:",
    r"on\w+\s*=",
    r"<iframe[^>]*>",
    r"<object[^>]*>",
    r"<embed[^>]*>",
    r"<applet[^>]*>",
    r"<meta[^>]*>",
    r"<link[^>]*>",
    r"<style[^>]*>.*?</style>",
    r"expression\s*\(",
    r"url\s*\(",
    r"@import"
]

COMMAND_INJECTION_PATTERNS = [
    r"[;&|`$(){}[\]\\]",
    r"\b(rm|del|format|fdisk|kill|shutdown|reboot|halt)\b",
    r"(>|>>|<|\|)",
    r"\$\{.*\}",
    r"`.*`",
    r"\$\(.*\)",
    r"\b(wget|curl|nc|netcat|telnet|ssh)\b",
    r"\b(chmod|chown|sudo|su)\b"
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e%5c",
    r"\.\.%2f",
    r"\.\.%5c",
    r"\.\.%252f",
    r"\.\.%255c"
]

COMPILED_PATTERNS = {
    "sql_injection": [re.compile(pattern, re.IGNORECASE) for pattern in SQL_INJECTION_PATTERNS],
    "xss": [re.compile(pattern, re.IGNORECASE) for pattern in XSS_PATTERNS],
    "command_injection": [re.compile(pattern, re.IGNORECASE) for pattern in COMMAND_INJECTION_PATTERNS],
    "path_traversal": [re.compile(pattern, re.IGNORECASE) for pattern in PATH_TRAVERSAL_PATTERNS]
}
