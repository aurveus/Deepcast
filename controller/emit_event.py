#!/usr/bin/env python3
"""Append a progress event to lab/logs/events.jsonl and update lab/logs/run_status.json.

Used by run_loop.sh so the dashboard can show a run while it happens.
  python controller/emit_event.py <event> [key=value ...]

Events that set the live stage: run_capture_started (capturing), run_saving (saving),
analysis_started (analyzing), controller_started (acting), run_finished (idle).
"""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LOGS = Path(__file__).resolve().parent.parent / "lab" / "logs"
STAGE_OF = {"run_capture_started": "capturing", "run_saving": "saving", "analysis_started": "analyzing",
            "controller_started": "acting", "run_finished": "idle"}


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    event, fields = sys.argv[1], dict(a.split("=", 1) for a in sys.argv[2:] if "=" in a)
    LOGS.mkdir(parents=True, exist_ok=True)
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "event": event, **fields}
    with (LOGS / "events.jsonl").open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(rec) + "\n")
    stage = STAGE_OF.get(event)
    if stage:
        status = LOGS / "run_status.json"
        old = json.loads(status.read_text(encoding="utf-8")) if status.exists() else {}
        started = old.get("started") if stage not in ("capturing", "idle") and old.get("stage") != "idle" else time.time()
        status.write_text(json.dumps({"stage": stage, "name": fields.get("name", old.get("name", "")),
                                      "started": started, "updated": time.time()}), encoding="utf-8")


if __name__ == "__main__":
    main()
