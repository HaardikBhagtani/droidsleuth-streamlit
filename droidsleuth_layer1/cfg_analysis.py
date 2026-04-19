from __future__ import annotations

from collections import Counter
from pathlib import Path

from .callgraph import AnalyzeAPK, _is_common_library_signature, _quiet_androguard, _to_signature


REFLECTION_PATTERNS = (
    "Ljava/lang/Class;->forName",
    "Ljava/lang/reflect/Method;->invoke",
    "Ljava/lang/reflect/Field;->get",
    "Ljava/lang/reflect/Constructor;->newInstance",
)

DYNAMIC_LOADING_PATTERNS = (
    "Ldalvik/system/DexClassLoader;-><init>",
    "Ldalvik/system/PathClassLoader;-><init>",
    "Ljava/lang/ClassLoader;->loadClass",
)

ANTI_ANALYSIS_PATTERNS = (
    "Landroid/os/Build;->FINGERPRINT",
    "Landroid/os/Build;->MODEL",
    "Landroid/os/Debug;->isDebuggerConnected",
    "Ljava/io/File;->exists",
    "Ljava/lang/System;->getProperty",
)


def _successor_count(block: object) -> int:
    try:
        next_blocks = block.get_next()
    except Exception:
        return 0
    if next_blocks is None:
        return 0
    if isinstance(next_blocks, (list, tuple, set)):
        return len(next_blocks)
    return 1


def analyze_control_flow(apk_path: str | Path, preview_limit: int = 10) -> dict:
    path = Path(apk_path)
    if AnalyzeAPK is None:
        return {
            "status": "unavailable",
            "error": "androguard is not installed",
            "features": {
                "reflection_usage_count": 0,
                "dynamic_class_loading_count": 0,
                "anti_analysis_branch_method_count": 0,
                "complex_cfg_method_count": 0,
                "max_basic_block_count": 0,
            },
            "suspicious_methods": [],
            "pattern_counts": {},
        }

    try:
        with _quiet_androguard():
            _, _, dx = AnalyzeAPK(str(path))
    except Exception as exc:  # pragma: no cover
        return {
            "status": "error",
            "error": str(exc),
            "features": {
                "reflection_usage_count": 0,
                "dynamic_class_loading_count": 0,
                "anti_analysis_branch_method_count": 0,
                "complex_cfg_method_count": 0,
                "max_basic_block_count": 0,
            },
            "suspicious_methods": [],
            "pattern_counts": {},
        }

    pattern_counts = Counter()
    suspicious_methods: list[str] = []
    anti_analysis_branch_method_count = 0
    complex_cfg_method_count = 0
    max_basic_block_count = 0

    for method_analysis in dx.get_methods():
        if method_analysis.is_external():
            continue
        method_signature = _to_signature(method_analysis.get_method())
        if _is_common_library_signature(method_signature):
            continue
        xref_signatures = [_to_signature(callee.get_method()) for _, callee, _ in method_analysis.get_xref_to()]
        basic_blocks_obj = method_analysis.get_basic_blocks()
        blocks = list(basic_blocks_obj.gets()) if hasattr(basic_blocks_obj, "gets") else list(basic_blocks_obj)
        block_count = len(blocks)
        max_basic_block_count = max(max_basic_block_count, block_count)
        branching_blocks = sum(1 for block in blocks if _successor_count(block) >= 2)

        reflection = any(any(pattern in signature for pattern in REFLECTION_PATTERNS) for signature in xref_signatures)
        dynamic_loading = any(
            any(pattern in signature for pattern in DYNAMIC_LOADING_PATTERNS) for signature in xref_signatures
        )
        anti_analysis = any(
            any(pattern in signature for pattern in ANTI_ANALYSIS_PATTERNS) for signature in xref_signatures
        )

        if reflection:
            pattern_counts["reflection"] += 1
        if dynamic_loading:
            pattern_counts["dynamic_loading"] += 1
        if anti_analysis:
            pattern_counts["anti_analysis"] += 1
        if block_count >= 5 or branching_blocks >= 2:
            complex_cfg_method_count += 1
        if anti_analysis and (block_count >= 4 or branching_blocks >= 1):
            anti_analysis_branch_method_count += 1
            if len(suspicious_methods) < preview_limit:
                suspicious_methods.append(method_signature)

    return {
        "status": "ok",
        "error": None,
        "features": {
            "reflection_usage_count": pattern_counts["reflection"],
            "dynamic_class_loading_count": pattern_counts["dynamic_loading"],
            "anti_analysis_branch_method_count": anti_analysis_branch_method_count,
            "complex_cfg_method_count": complex_cfg_method_count,
            "max_basic_block_count": max_basic_block_count,
        },
        "suspicious_methods": suspicious_methods,
        "pattern_counts": dict(sorted(pattern_counts.items())),
    }
