#!/usr/bin/env python3
"""Streaming rule engine: feed it events one at a time, it answers at once. No windows, no batches.

  python detect/engine.py --selftest

  engine = RuleEngine(rules)            # rules already validated by rules.py
  for alert in engine.feed(event): ...  # event dicts from events.py, in time order

State is a sliding window per (rule, clause, client): a deque of the events that matched the clause plus a
counter for distinct measures, so one event costs O(1) amortised. The clock is the event time, so a replayed pcap
and live traffic behave the same. Memory is bounded: clients quiet for longer than the rule's window are dropped,
and at most MAX_CLIENTS are tracked per rule (the least recently seen is evicted first).
"""
import sys
from collections import OrderedDict, deque

from rules import validate_ruleset

MAX_CLIENTS = 5000
KEY = {"count": None, "distinct_dport": "dport", "distinct_path": "path_hash", "distinct_server": "server"}


def _matches(clause, ev):
    if ev["kind"] != clause["kind"]:
        return False
    if "dport_in" in clause and ev.get("dport") not in clause["dport_in"]:
        return False
    if "dport_not_in" in clause and ev.get("dport") in clause["dport_not_in"]:
        return False
    if "method_in" in clause and ev.get("method") not in clause["method_in"]:
        return False
    if "status_in" in clause and ev.get("status") not in clause["status_in"]:
        return False
    if clause.get("trap") and not ev.get("trap"):
        return False
    return True


class _Window:
    """Events of one clause for one client inside the last `span` seconds."""

    def __init__(self, measure):
        self.key, self.items, self.counts = KEY[measure], deque(), {}

    def add(self, t, ev, span):
        k = ev.get(self.key) if self.key else None
        self.items.append((t, k))
        self.counts[k] = self.counts.get(k, 0) + 1
        self.trim(t, span)

    def trim(self, now, span):
        while self.items and self.items[0][0] < now - span:
            _, k = self.items.popleft()
            self.counts[k] -= 1
            if not self.counts[k]:
                del self.counts[k]

    def value(self, measure):
        return len(self.items) if measure == "count" else len(self.counts)


class RuleEngine:
    def __init__(self, rules, ignore_clients=()):
        errs = validate_ruleset(rules)
        if errs:
            raise ValueError("; ".join(errs))
        self.rules = rules
        self.ignore = set(ignore_clients)
        self.state = {r["id"]: OrderedDict() for r in rules}          # rule id -> client -> {"w": [windows], "first": t, "fired": t}
        self.by_kind = {}
        for r in rules:
            for i, c in enumerate(r["all_of"]):
                self.by_kind.setdefault(c["kind"], []).append((r, i, c))

    def feed(self, ev):
        """Process one event; return the alerts it caused (usually none)."""
        client = ev["client"]
        if client in self.ignore:
            return []
        alerts, touched = [], {}
        for rule, i, clause in self.by_kind.get(ev["kind"], ()):
            if not _matches(clause, ev):
                continue
            st = self._client_state(rule, client, ev["t"])
            st["w"][i].add(ev["t"], ev, rule["window_s"])
            touched[rule["id"]] = (rule, st)
        for rule, st in touched.values():
            alert = self._check(rule, client, st, ev["t"])
            if alert:
                alerts.append(alert)
        return alerts

    def _client_state(self, rule, client, now):
        clients = self.state[rule["id"]]
        st = clients.pop(client, None)
        if st is None:
            st = {"w": [_Window(c["measure"]) for c in rule["all_of"]], "first": now, "fired": None}
            while len(clients) >= MAX_CLIENTS:
                clients.popitem(last=False)
        clients[client] = st                                        # most recently seen goes last
        return st

    def _check(self, rule, client, st, now):
        values = []
        for w, c in zip(st["w"], rule["all_of"]):
            w.trim(now, rule["window_s"])                            # other clauses may have gone stale since their last event
            values.append(w.value(c["measure"]))
        if not all(v >= c["value"] for v, c in zip(values, rule["all_of"])):
            return None
        if st["fired"] is not None and now - st["fired"] < rule.get("refire_s", 60):
            return None
        st["fired"] = now
        return {"rule_id": rule["id"], "rule_name": rule["name"], "technique": rule.get("technique"), "client": client,
                "t": now, "first_seen": st["first"], "latency_since_first_s": round(now - st["first"], 3),
                "observed": [{"measure": c["measure"], "kind": c["kind"], "value": v, "needed": c["value"]} for v, c in zip(values, rule["all_of"])]}

    def expire(self, now):
        """Drop clients that have been silent for longer than their rule's window (call now and then on long streams)."""
        for rule in self.rules:
            clients = self.state[rule["id"]]
            for client in [c for c, st in clients.items() if all(not w.items or w.items[-1][0] < now - rule["window_s"] for w in st["w"])
                           and (st["fired"] is None or st["fired"] < now - rule.get("refire_s", 60))]:
                del clients[client]


def run(rules, events, ignore_clients=()):
    """Replay a list of events (time-sorted) through a fresh engine; return all alerts."""
    eng = RuleEngine(rules, ignore_clients)
    return [a for ev in events for a in eng.feed(ev)]


def _selftest():
    scan = {"id": "SCAN", "name": "scan", "origin": "baseline", "window_s": 10, "all_of": [{"kind": "syn", "measure": "distinct_dport", "op": ">=", "value": 5}]}
    mix = {"id": "MIX", "name": "404 storm from a few paths", "origin": "baseline", "window_s": 10, "refire_s": 5,
           "all_of": [{"kind": "http_resp", "status_in": [404], "measure": "count", "op": ">=", "value": 3},
                      {"kind": "http_req", "measure": "distinct_path", "op": ">=", "value": 3}]}
    syn = lambda t, c, p: {"t": t, "client": c, "server": "S", "kind": "syn", "dport": p}
    # distinct ports inside the window fire at the fifth port; repeats of one port never do
    a = run([scan], [syn(i, "A", 100 + i) for i in range(5)])
    assert len(a) == 1 and a[0]["t"] == 4 and a[0]["latency_since_first_s"] == 4
    assert run([scan], [syn(i, "A", 100) for i in range(50)]) == []
    # slow: ports spread over more than the window never fire
    assert run([scan], [syn(i * 3, "A", 100 + i) for i in range(10)]) == []
    # sources are independent
    assert run([scan], [syn(i, "AB"[i % 2], 100 + i) for i in range(8)]) == []
    # ignored clients
    assert run([scan], [syn(i, "H", 100 + i) for i in range(9)], ignore_clients=["H"]) == []
    # re-fire suppression: one alert per refire period (default 60 s)
    assert len(run([scan], [syn(i, "A", 100 + i % 7) for i in range(50)])) == 1
    assert len(run([scan], [syn(i, "A", 100 + i % 7) for i in range(130)])) == 3
    # two clauses must hold together, in the same window
    req = lambda t, h: {"t": t, "client": "A", "server": "S", "kind": "http_req", "dport": 80, "method": "GET", "path_hash": h, "trap": False}
    resp = lambda t, s: {"t": t, "client": "A", "server": "S", "kind": "http_resp", "dport": 80, "status": s}
    ev = [req(0, "a"), resp(0.1, 404), req(1, "b"), resp(1.1, 404), req(2, "c"), resp(2.1, 200)]
    assert run([mix], ev) == []
    assert len(run([mix], ev + [resp(2.2, 404)])) == 1
    assert run([mix], [req(0, "a"), req(1, "a"), req(2, "a")] + [resp(3 + i, 404) for i in range(4)]) == []       # one path only
    # a stale clause does not keep a rule armed
    assert run([mix], [req(0, "a"), req(0.5, "b"), req(1, "c"), resp(30, 404), resp(31, 404), resp(32, 404)]) == []
    # filters: ports, methods, trap
    trap = {"id": "TRAP", "name": "trap", "origin": "baseline", "window_s": 60, "all_of": [{"kind": "http_req", "trap": True, "method_in": ["GET"], "dport_in": [80], "measure": "count", "op": ">=", "value": 1}]}
    assert len(run([trap], [{**req(0, "a"), "trap": True}])) == 1
    assert run([trap], [req(0, "a")]) == [] and run([trap], [{**req(0, "a"), "trap": True, "method": "POST"}]) == []
    # bounded memory
    eng = RuleEngine([scan])
    for i in range(MAX_CLIENTS + 100):
        eng.feed(syn(i * 0.001, f"C{i}", 1))
    assert len(eng.state["SCAN"]) == MAX_CLIENTS
    eng.expire(1e9)
    assert len(eng.state["SCAN"]) == 0
    try:
        RuleEngine([{**scan, "window_s": 0}])
        raise SystemExit("invalid rule accepted")
    except ValueError:
        pass
    print("engine selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        sys.exit(__doc__)
