import re

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*).*$", re.MULTILINE),
    re.compile(r"(?i)(cookie\s*:\s*).*$", re.MULTILINE),
    re.compile(r"(?i)(api[-_ ]?key\s*[:=]\s*).*$", re.MULTILINE),
    re.compile(r"(?i)(password\s*[:=]\s*).*$", re.MULTILINE),
]


def redact(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text
