"""pySigma conversion: Sigma YAML → Splunk SPL / Elastic Lucene / Sentinel KQL.

Each backend is instantiated lazily because the kusto backend's import is
heavyish. Errors from a single rule are caught and returned per-rule so a
batch of N rules still surfaces the (N-1) that worked.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Iterable

from sigma.collection import SigmaCollection

log = logging.getLogger(__name__)


class SigmaBackend(str, Enum):
    SPLUNK = "splunk"
    ELASTIC = "elastic"  # Lucene/KQL flavour used by Kibana
    SENTINEL = "sentinel"  # KQL — Azure Sentinel / Defender XDR


def _backend_instance(backend: SigmaBackend):
    # Lazy import keeps app start fast and isolates backend-specific deps.
    if backend == SigmaBackend.SPLUNK:
        from sigma.backends.splunk import SplunkBackend
        return SplunkBackend()
    if backend == SigmaBackend.ELASTIC:
        from sigma.backends.elasticsearch import LuceneBackend
        return LuceneBackend()
    if backend == SigmaBackend.SENTINEL:
        from sigma.backends.kusto import KustoBackend
        return KustoBackend()
    raise ValueError(f"unknown backend: {backend!r}")


def convert_yaml(raw_yaml: str, backend: SigmaBackend) -> list[str]:
    """Convert a single Sigma YAML document to one or more backend queries."""
    if not raw_yaml or not raw_yaml.strip():
        raise ValueError("empty YAML")
    col = SigmaCollection.from_yaml(raw_yaml)
    inst = _backend_instance(backend)
    result = inst.convert(col)
    # pySigma always returns a list[str] (per-rule queries).
    return [str(q) for q in result]


def convert_many(
    rows: Iterable[tuple[str, str]],
    backend: SigmaBackend,
) -> list[dict]:
    """Convert (id, raw_yaml) pairs. Failures land in `error` instead of raising."""
    backend_inst = _backend_instance(backend)
    out: list[dict] = []
    for det_id, raw in rows:
        if not raw or not raw.strip():
            out.append(
                {
                    "detection_id": det_id,
                    "queries": [],
                    "error": "empty YAML",
                }
            )
            continue
        try:
            col = SigmaCollection.from_yaml(raw)
            queries = [str(q) for q in backend_inst.convert(col)]
            out.append({"detection_id": det_id, "queries": queries, "error": None})
        except Exception as e:
            out.append(
                {
                    "detection_id": det_id,
                    "queries": [],
                    "error": f"{type(e).__name__}: {e}",
                }
            )
    return out


__all__ = ["SigmaBackend", "convert_many", "convert_yaml"]
