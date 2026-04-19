from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from pathlib import Path


URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{6,}")
DOMAIN_RE = re.compile(rb"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.IGNORECASE)
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BASE64_RE = re.compile(rb"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
HEX_RE = re.compile(rb"\b(?:[0-9a-fA-F]{2}){12,}\b")

SUSPICIOUS_TLDS = ("xyz", "top", "click", "work", "live", "shop", "site", "info")
SUSPICIOUS_HOST_TOKENS = ("duckdns", "ngrok", "pastebin", "telegram", "discord", "bit.ly", "tinyurl")
KNOWN_TLDS = {
    b"com", b"net", b"org", b"edu", b"gov", b"mil", b"io", b"co", b"in", b"me", b"cc",
    b"xyz", b"top", b"click", b"work", b"live", b"shop", b"site", b"info", b"ru", b"cn",
    b"biz", b"app", b"dev", b"cloud", b"online", b"pro",
}
FAKE_DOMAIN_SUFFIXES = (
    b".version",
    b".versionpk",
    b".versionkeys",
    b".properties",
    b".xml",
    b".json",
    b".proto",
    b".txt",
)


def _safe_ascii(values: set[bytes], limit: int = 12) -> list[str]:
    decoded = []
    for value in values:
        try:
            decoded.append(value.decode("utf-8", errors="replace"))
        except Exception:
            decoded.append(repr(value))
    return sorted(decoded)[:limit]


def _decode_obfuscated_candidates(blob: bytes) -> tuple[set[bytes], set[bytes]]:
    decoded_urls: set[bytes] = set()
    decoded_domains: set[bytes] = set()

    for candidate in BASE64_RE.findall(blob):
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except Exception:
            continue
        if URL_RE.search(decoded):
            decoded_urls.update(URL_RE.findall(decoded))
        decoded_domains.update(DOMAIN_RE.findall(decoded))

    for candidate in HEX_RE.findall(blob):
        try:
            decoded = binascii.unhexlify(candidate)
        except Exception:
            continue
        if URL_RE.search(decoded):
            decoded_urls.update(URL_RE.findall(decoded))
        decoded_domains.update(DOMAIN_RE.findall(decoded))

    return decoded_urls, decoded_domains


def _looks_like_real_domain(domain: bytes) -> bool:
    decoded = domain.decode("utf-8", errors="ignore")
    lowered = domain.lower()
    if len(lowered) <= 8 or lowered.startswith(b"-"):
        return False
    if any(lowered.endswith(suffix) for suffix in FAKE_DOMAIN_SUFFIXES):
        return False
    parts = lowered.split(b".")
    original_parts = decoded.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld not in KNOWN_TLDS:
        return False
    if any(not part or part.startswith(b"-") or part.endswith(b"-") for part in parts):
        return False
    for original_part, lowered_part in zip(original_parts[:-1], parts[:-1]):
        if not lowered_part:
            return False
        if any(ch.isupper() for ch in original_part):
            return False
        if not any(chr(byte).islower() for byte in lowered_part if 97 <= byte <= 122):
            return False
    return True


def analyze_c2_indicators(apk_path: str | Path) -> dict:
    blob = Path(apk_path).read_bytes()
    urls = set(URL_RE.findall(blob))
    domains = {domain for domain in DOMAIN_RE.findall(blob) if _looks_like_real_domain(domain)}
    ips = {item for item in IP_RE.findall(blob) if not item.startswith(b"127.")}
    decoded_urls, decoded_domains = _decode_obfuscated_candidates(blob)
    decoded_domains = {domain for domain in decoded_domains if _looks_like_real_domain(domain)}

    suspicious = Counter()
    for url in urls | decoded_urls:
        lowered = url.decode("utf-8", errors="ignore").lower()
        if any(token in lowered for token in SUSPICIOUS_HOST_TOKENS):
            suspicious["known_suspicious_service"] += 1
        if re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", lowered):
            suspicious["raw_ip_c2"] += 1
    for domain in domains | decoded_domains:
        lowered = domain.decode("utf-8", errors="ignore").lower()
        if any(lowered.endswith(f".{tld}") for tld in SUSPICIOUS_TLDS):
            suspicious["suspicious_tld"] += 1
        if any(token in lowered for token in SUSPICIOUS_HOST_TOKENS):
            suspicious["known_suspicious_service"] += 1

    return {
        "status": "ok",
        "features": {
            "url_count": len(urls),
            "domain_count": len(domains),
            "ip_count": len(ips),
            "decoded_url_count": len(decoded_urls),
            "decoded_domain_count": len(decoded_domains),
            "suspicious_network_indicator_count": sum(suspicious.values()),
        },
        "urls": _safe_ascii(urls),
        "domains": _safe_ascii(domains),
        "ips": _safe_ascii(ips),
        "decoded_urls": _safe_ascii(decoded_urls),
        "decoded_domains": _safe_ascii(decoded_domains),
        "pattern_counts": dict(sorted(suspicious.items())),
    }
