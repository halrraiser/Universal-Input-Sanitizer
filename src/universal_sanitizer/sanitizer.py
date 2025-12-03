"""
Core sanitizer utilities.

This module focuses on concise, readable implementations that are easy to extend.
Comments explain why functions exist and give examples of intended behavior.
"""

import re
import json
from typing import Optional, Tuple

# Simple regexes for common types. These are intentionally conservative and easy to read.
_EMAIL_RE = re.compile(r"(?P<local>[^@\s]+)@(?P<domain>[^\s@]+\.[^\s@]+)")
_PHONE_RE = re.compile(r"\+?\d[\d\-() ]{6,}\d")
_URL_RE = re.compile(r"https?://[^\s]+")



# Masking utilities
def mask_email(value: str) -> str:
    """
    Mask an email address to protect user privacy while keeping it recognizable.
    Example: 'alice@example.com' -> 'a***e@e*****m'
    """
    m = _EMAIL_RE.search(value)
    if not m:
        return value
    local = m.group("local")
    domain = m.group("domain")

    def mask_part(s: str) -> str:
        if not s:
            return ""
        if len(s) == 1:
            return s + "*"
        if len(s) == 2:
            return s[0] + "*"
        return s[0] + "*" * (len(s) - 2) + s[-1]

    domain_masked = ".".join(mask_part(label) for label in domain.split("."))
    return f"{mask_part(local)}@{domain_masked}"


def mask_phone(value: str) -> str:
    """
    Replace digits in phone number leaving last 2 visible.
    Keeps delimiting characters like +, -, spaces.
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "*" * len(digits)
    keep = 2
    masked_digits = "*" * (len(digits) - keep) + digits[-keep:]

    it = iter(masked_digits)
    out = []
    for ch in value:
        if ch.isdigit():
            out.append(next(it))
        else:
            out.append(ch)
    return "".join(out)


def strip_url_query(value: str) -> str:
    """
    Remove query parameters from URLs to avoid leaking tokens and tracking params.
    """
    return re.sub(r"(https?://[^\s?]+)\?.*", r"\1", value)


def escape_sql(value: str) -> str:
    """
    Basic SQL string escape: double single-quotes.
    This is *not* a full SQL sanitizer for untrusted queries.
    """
    return value.replace("'", "''")


def html_escape(value: str) -> str:
    """
    Escape characters that are dangerous when injected into HTML.
    """
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )

# Type detection
def detect_type(value: str) -> str:
    """
    Very lightweight detection of value type.
    Returns one of: 'email', 'phone', 'url', 'json', 'env', 'text'
    """
    v = value.strip()

    # JSON detection first
    if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
        try:
            json.loads(v)
            return "json"
        except Exception:
            pass

    # ENV detection next
    if "=" in v:
        lines = [ln for ln in v.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if lines and all("=" in ln for ln in lines):
            return "env"

    # Emails, phone, urls after JSON/env
    if _EMAIL_RE.fullmatch(v):
        return "email"
    if _PHONE_RE.fullmatch(v):
        return "phone"
    if _URL_RE.fullmatch(v):
        return "url"

    # Default to plain text
    return "text"

# Language literal escaping
def _python_literal(s: str) -> str:
    return repr(s)

def _js_literal(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

def _java_literal(s: str) -> str:
    esc = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return '"' + esc + '"'

def _c_literal(s: str) -> str:
    esc = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return '"' + esc + '"'

def _bash_literal(s: str) -> str:
    if "'" not in s:
        return "'" + s + "'"
    esc = s.replace("'", "'\\''")
    return "'" + esc + "'"

_LANGUAGE_ESCAPERS = {
    "python": _python_literal,
    "javascript": _js_literal,
    "js": _js_literal,
    "java": _java_literal,
    "go": _c_literal,
    "c": _c_literal,
    "csharp": _c_literal,
    "cs": _c_literal,
    "php": _c_literal,
    "ruby": _c_literal,
    "rust": _c_literal,
    "swift": _c_literal,
    "bash": _bash_literal,
}

def language_escape(s: str, language: str) -> str:
    """
    Return a string literal safe to paste into `language`.
    Falls back to Python repr if language is unknown.
    """
    fn = _LANGUAGE_ESCAPERS.get(language.lower())
    if fn:
        return fn(s)
    return _python_literal(s)

# Main sanitization
def sanitize_value(value: str, kind: Optional[str] = None) -> Tuple[str, str]:
    """
    Sanitize a single value.
    Returns: (detected_kind, sanitized_value)
    - kind: optional override (e.g., 'email', 'phone', 'url', 'text', 'json', 'env')
    """
    detected = kind or detect_type(value)
    v = value

    if detected == "email":
        return detected, mask_email(v)
    if detected == "phone":
        return detected, mask_phone(v)
    if detected == "url":
        return detected, strip_url_query(v)

    if detected == "json":
        try:
            obj = json.loads(v)

            def recurse(o):
                if isinstance(o, dict):
                    return {k: recurse(val) for k, val in o.items()}
                if isinstance(o, list):
                    return [recurse(i) for i in o]
                if isinstance(o, str):
                    t = detect_type(o)
                    return sanitize_value(o, t)[1]
                return o

            sanitized = recurse(obj)
            return detected, json.dumps(sanitized, ensure_ascii=False)
        except Exception:
            return "text", html_escape(v)

    if detected == "env":
        lines = []
        for line in v.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                lines.append(line)
                continue
            if "=" not in line:
                lines.append(line)
                continue
            k, val = line.split("=", 1)
            t = detect_type(val.strip())
            sanitized_val = sanitize_value(val.strip(), t)[1]
            lines.append(f"{k}={sanitized_val}")
        return detected, "\n".join(lines)

    # Default for text
    escaped = html_escape(escape_sql(v))
    return "text", escaped
