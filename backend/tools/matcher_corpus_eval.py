"""Evaluate the pragmatic Sigma matcher against a real ruleset.

Iterates every detection in `public.default_detections` (the seeded
SigmaHQ catalog), runs each rule against a synthetic "match-anything"
event, and tallies how many decisions land in each bucket:

  - matched          → rule clearly fires on the synthetic event
  - not matched      → rule clearly doesn't fire
  - indeterminate    → matcher returned (None, reason) — bucketed by reason

The point isn't to test detection accuracy (the synthetic event matches
nothing realistic); it's to surface which Sigma surface area we still
can't evaluate cleanly. Run after pulling a fresh SigmaHQ ruleset.

    docker compose exec backend python -m tools.matcher_corpus_eval

Reads the catalog row by row and prints a summary at the end. No DB
writes. Safe to run in production.
"""
from __future__ import annotations

import asyncio
import collections
import logging
from typing import Optional

from sqlalchemy import select

from app.db.base import AsyncSessionLocal
from app.models.public import DefaultDetection
from app.services.detection_samples import match_event

log = logging.getLogger(__name__)


# A synthetic event with the most common Sigma field names; the matcher
# can pattern-match against these without us actually mocking each rule's
# log source. The values are obviously bogus — the goal is to exercise
# the matcher, not to fire real detections.
SYNTHETIC_EVENT = {
    "Image": r"C:\Windows\System32\powershell.exe",
    "CommandLine": "powershell -enc dGVzdA==",
    "User": "alice",
    "ParentImage": r"C:\Windows\explorer.exe",
    "ProcessName": "powershell.exe",
    "EventID": 4688,
    "EventType": "process_start",
    "TargetFilename": r"C:\Temp\file.txt",
    "DestinationIp": "10.0.0.1",
    "SourceIp": "10.0.0.2",
    "Hashes": "MD5=abc;SHA256=def",
    "ScriptBlockText": "$shell = New-Object ...",
    "Provider_Name": "Microsoft-Windows-Sysmon",
    "Severity": 5,
}


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    matched = 0
    not_matched = 0
    indeterminate = 0
    reasons: collections.Counter[str] = collections.Counter()

    async with AsyncSessionLocal() as session:
        rows = (await session.execute(select(DefaultDetection))).scalars().all()
    total = len(rows)
    log.info("loaded %d rules from public.default_detections", total)

    for d in rows:
        body = d.detection or {}
        try:
            ok, msg = match_event(body, SYNTHETIC_EVENT)
        except Exception as e:  # noqa: BLE001 - we WANT to see crashes
            indeterminate += 1
            reasons[f"crash: {type(e).__name__}"] += 1
            continue
        if ok is True:
            matched += 1
        elif ok is False:
            not_matched += 1
        else:
            indeterminate += 1
            # Bucket reasons coarsely: take the first comma-prefix.
            bucket = (msg or "unknown")[:80].split(":")[0].strip()
            reasons[bucket] += 1

    log.info("-" * 50)
    log.info("Sigma matcher corpus evaluation")
    log.info("-" * 50)
    log.info("rules total:       %d", total)
    log.info("matched:           %d (%.1f%%)", matched, 100 * matched / max(total, 1))
    log.info("not matched:       %d (%.1f%%)", not_matched, 100 * not_matched / max(total, 1))
    log.info("indeterminate:     %d (%.1f%%)", indeterminate, 100 * indeterminate / max(total, 1))
    log.info("")
    log.info("indeterminate breakdown:")
    for reason, n in reasons.most_common():
        log.info("  %-50s %d", reason, n)


if __name__ == "__main__":
    asyncio.run(main())
