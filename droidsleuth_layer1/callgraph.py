from __future__ import annotations

import logging
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


try:
    from androguard.misc import AnalyzeAPK
except ImportError:  # pragma: no cover - dependency may be absent in some environments
    AnalyzeAPK = None

try:  # pragma: no cover - optional dependency detail
    from loguru import logger as loguru_logger
except ImportError:  # pragma: no cover
    loguru_logger = None


LOGGER_NAMES = (
    "androguard",
    "androguard.misc",
    "androguard.core.analysis.analysis",
    "androguard.core.apk",
    "androguard.core.axml",
)

COMMON_LIBRARY_PREFIXES = (
    "Landroid/",
    "Landroidx/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Lcom/google/",
    "Lcom/facebook/",
    "Lokhttp3/",
    "Lretrofit2/",
    "Lokio/",
    "Lorg/apache/",
    "Lorg/json/",
    "Lorg/xml/",
    "Lj$/",
)

CALL_SEQUENCE_RULES = {
    "sms_abuse": (
        "Landroid/telephony/SmsManager;->sendTextMessage",
        "Landroid/telephony/SmsManager;->sendMultipartTextMessage",
        "Landroid/telephony/SmsManager;->sendDataMessage",
    ),
    "overlay_attack": (
        "Landroid/view/WindowManager;->addView",
        "Landroid/provider/Settings;->canDrawOverlays",
        "Landroid/view/accessibility/AccessibilityEvent;",
        "Landroid/accessibilityservice/AccessibilityService;",
    ),
    "credential_harvesting": (
        "Landroid/view/accessibility/AccessibilityNodeInfo;",
        "Landroid/webkit/WebView;->addJavascriptInterface",
        "Landroid/webkit/WebView;->loadUrl",
        "Landroid/view/inputmethod/InputMethodManager;",
    ),
    "dynamic_code_loading": (
        "Ldalvik/system/DexClassLoader;-><init>",
        "Ldalvik/system/PathClassLoader;-><init>",
        "Ljava/lang/ClassLoader;->loadClass",
    ),
    "dropper_install_flow": (
        "Landroid/content/Intent;->setDataAndType",
        "Landroid/content/Intent;->setData",
        "Landroid/content/Context;->startActivity",
        "Landroid/content/pm/PackageInstaller;",
    ),
    "network_exfiltration": (
        "Ljava/net/HttpURLConnection;->connect",
        "Lokhttp3/OkHttpClient;",
        "Lretrofit2/Retrofit;",
        "Ljavax/net/ssl/HttpsURLConnection;",
    ),
}

SENSITIVE_API_GROUPS = {
    "sms": CALL_SEQUENCE_RULES["sms_abuse"],
    "overlay": CALL_SEQUENCE_RULES["overlay_attack"],
    "credential": CALL_SEQUENCE_RULES["credential_harvesting"],
    "dynamic_loading": CALL_SEQUENCE_RULES["dynamic_code_loading"],
    "package_install": CALL_SEQUENCE_RULES["dropper_install_flow"],
    "network": CALL_SEQUENCE_RULES["network_exfiltration"],
    "telephony_id": (
        "Landroid/telephony/TelephonyManager;->getDeviceId",
        "Landroid/telephony/TelephonyManager;->getSubscriberId",
        "Landroid/telephony/TelephonyManager;->getImei",
        "Landroid/telephony/TelephonyManager;->getLine1Number",
    ),
    "contacts": (
        "Landroid/content/ContentResolver;->query",
        "Landroid/provider/ContactsContract",
    ),
    "runtime_exec": (
        "Ljava/lang/Runtime;->exec",
        "Ljava/lang/ProcessBuilder;-><init>",
    ),
}


def _method_id(class_name: str, name: str, descriptor: str) -> str:
    return f"{class_name}->{name}{descriptor}"


def _to_signature(method_obj: object) -> str:
    class_name = getattr(method_obj, "get_class_name", None)
    name = getattr(method_obj, "get_name", None)
    descriptor = getattr(method_obj, "get_descriptor", None)
    if callable(class_name) and callable(name) and callable(descriptor):
        return _method_id(class_name(), name(), descriptor())
    return str(method_obj)


def _is_common_library_signature(signature: str) -> bool:
    return signature.startswith(COMMON_LIBRARY_PREFIXES)


@contextmanager
def _quiet_androguard():
    loggers = [logging.getLogger(name) for name in LOGGER_NAMES]
    previous_levels = [logger.level for logger in loggers]
    previous_disabled = [logger.disabled for logger in loggers]
    loguru_handler_id = None
    try:
        for logger in loggers:
            logger.disabled = True
            logger.setLevel(logging.CRITICAL)
        if loguru_logger is not None:
            loguru_handler_id = loguru_logger.add(lambda _: None, level="CRITICAL")
        yield
    finally:
        for logger, level, disabled in zip(loggers, previous_levels, previous_disabled):
            logger.disabled = disabled
            logger.setLevel(level)
        if loguru_logger is not None and loguru_handler_id is not None:
            try:
                loguru_logger.remove(loguru_handler_id)
            except Exception:
                pass


@dataclass
class CallGraphSummary:
    status: str
    method_count: int
    internal_method_count: int
    external_call_edge_count: int
    internal_call_edge_count: int
    sensitive_api_counts: dict[str, int]
    behavioral_sequences: list[str]
    suspicious_method_samples: list[str]
    error: str | None = None


def analyze_api_call_graph(apk_path: str | Path, preview_limit: int = 12) -> dict:
    path = Path(apk_path)
    if AnalyzeAPK is None:
        return {
            "status": "unavailable",
            "error": "androguard is not installed",
            "features": {
                "method_count": 0,
                "internal_method_count": 0,
                "external_call_edge_count": 0,
                "internal_call_edge_count": 0,
                "behavioral_sequence_count": 0,
                "sensitive_api_total": 0,
            },
            "behavioral_sequences": [],
            "suspicious_method_samples": [],
            "sensitive_api_counts": {},
        }

    try:
        with _quiet_androguard():
            _, _, dx = AnalyzeAPK(str(path))
    except Exception as exc:  # pragma: no cover - depends on APK quality / dependency behavior
        return {
            "status": "error",
            "error": str(exc),
            "features": {
                "method_count": 0,
                "internal_method_count": 0,
                "external_call_edge_count": 0,
                "internal_call_edge_count": 0,
                "behavioral_sequence_count": 0,
                "sensitive_api_total": 0,
            },
            "behavioral_sequences": [],
            "suspicious_method_samples": [],
            "sensitive_api_counts": {},
        }

    sensitive_counts = Counter()
    suspicious_methods: list[str] = []
    method_count = 0
    internal_method_count = 0
    external_edges = 0
    internal_edges = 0
    behavioral_sequences: set[str] = set()

    for method_analysis in dx.get_methods():
        method_count += 1
        if method_analysis.is_external():
            continue

        method_signature = _to_signature(method_analysis.get_method())
        if _is_common_library_signature(method_signature):
            continue

        internal_method_count += 1
        xrefs = list(method_analysis.get_xref_to())
        signatures = [_to_signature(callee.get_method()) for _, callee, _ in xrefs]

        method_groups = {
            label
            for label, patterns in SENSITIVE_API_GROUPS.items()
            if any(any(pattern in signature for pattern in patterns) for signature in signatures)
        }
        method_sensitive_groups: set[str] = set()

        for class_analysis, callee, _ in xrefs:
            if getattr(callee, "is_external", lambda: False)():
                external_edges += 1
            else:
                internal_edges += 1
            callee_signature = _to_signature(callee.get_method())
            for label, patterns in SENSITIVE_API_GROUPS.items():
                if any(pattern in callee_signature for pattern in patterns):
                    method_sensitive_groups.add(label)
            if getattr(class_analysis, "is_external", lambda: False)():
                external_edges += 0

        for label in method_sensitive_groups:
            sensitive_counts[label] += 1

        if {"overlay", "credential"} <= method_groups and (
            "sms" in method_groups or "telephony_id" in method_groups or "network" in method_groups
        ):
            behavioral_sequences.add("overlay_attack_sequence")
        if {"sms", "telephony_id"} & method_groups and "network" in method_groups:
            behavioral_sequences.add("sms_or_deviceid_with_network_sequence")
        if "dynamic_loading" in method_groups and ("package_install" in method_groups or "runtime_exec" in method_groups):
            behavioral_sequences.add("dropper_loader_sequence")
        if "credential" in method_groups and "network" in method_groups:
            behavioral_sequences.add("credential_exfiltration_sequence")
        if {"telephony_id", "contacts"} & method_groups and "network" in method_groups:
            behavioral_sequences.add("device_or_contact_exfiltration_sequence")

        if len(method_groups) >= 2 and len(suspicious_methods) < preview_limit:
            suspicious_methods.append(method_signature)

    sensitive_api_edge_hits = sum(sensitive_counts.values())
    sensitive_api_category_count = len([count for count in sensitive_counts.values() if count > 0])
    return {
        "status": "ok",
        "error": None,
        "features": {
            "method_count": method_count,
            "internal_method_count": internal_method_count,
            "external_call_edge_count": external_edges,
            "internal_call_edge_count": internal_edges,
            "behavioral_sequence_count": len(behavioral_sequences),
            "sensitive_api_total": sensitive_api_category_count,
            "sensitive_api_edge_hits": sensitive_api_edge_hits,
        },
        "behavioral_sequences": sorted(behavioral_sequences),
        "suspicious_method_samples": suspicious_methods[:preview_limit],
        "sensitive_api_counts": dict(sorted(sensitive_counts.items())),
    }
