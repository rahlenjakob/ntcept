#!/usr/bin/env python3
"""ntcept scripting harness.

ntcept runs this; it is not written by the user. It loads the user's script, gives it the state and
verdict helpers it calls, and speaks ntcept's line protocol:

  stdin   one JSON request per line  -- an event to judge, or a command (reload/reset/ping)
  stdout  one JSON reply per line    -- the verdict, or an ack; strictly one reply per request
  stderr  free-form                  -- the user's print()/log() and any traceback; ntcept tails it

The user writes on_request(m) / on_response(m) (or a single handle(m)); returning None passes the
message through. `state` is a dict that survives across every message and across reloads (reset
clears it); `m.ctx` is a per-exchange dict shared between a request and its response.
"""
import sys
import json
import time
import random
import traceback

STATE = {}          # global, persists across messages and reloads
CTX = {}            # exchange id -> dict
CTX_ORDER = []      # for bounded eviction
CTX_MAX = 10000

USER = None         # the user module's namespace
USER_PATH = sys.argv[1] if len(sys.argv) > 1 else ""


def _ctx_for(xid):
    c = CTX.get(xid)
    if c is None:
        c = CTX[xid] = {}
        CTX_ORDER.append(xid)
        if len(CTX_ORDER) > CTX_MAX:
            CTX.pop(CTX_ORDER.pop(0), None)
    return c


# --- verdict builders, injected into the user's namespace ---

def _v(action, delay=0, **kw):
    d = {"action": action}
    if delay:
        d["delay_ms"] = int(delay)
    d.update({k: v for k, v in kw.items() if v is not None})
    return d


def drop(delay=0):
    return _v("drop", delay)


def delay(ms):
    return _v("pass", ms)


def edit(sql=None, row=None, raw=None, body=None, status=0, set_headers=None,
         method=None, url=None, delay=0):
    return _v("edit", delay, sql=sql, row=row, raw=raw, body=body, status=(status or None),
              set_headers=set_headers, method=method, url=url)


def respond(pg_error=None, pg_code=None, pg_message=None, status=0, body=None, delay=0):
    return _v("respond", delay, pg_error=pg_error, pg_code=pg_code, pg_message=pg_message,
              status=(status or None), body=body)


def hold():
    return _v("hold")


def record(text=None, redact=None):
    return _v("record", record_text=text, record_redact=redact)


_logbuf = []


def log(*args):
    # Collected per message and returned with the verdict, so ntcept can attach these lines to the
    # exact request that produced them. Also echoed to stderr for the live `script logs` tail.
    line = " ".join(str(a) for a in args)
    _logbuf.append(line)
    print("[script]", line, file=sys.stderr, flush=True)


class Msg:
    """One intercepted message, as the user's hook sees it."""

    def __init__(self, ev):
        self._ev = ev
        self.id = ev.get("id", "")
        self.kind = ev.get("kind", "")
        self.proto = ev.get("proto", "")
        self.host = ev.get("host", "")
        self.port = ev.get("port", 0)
        self.direction = ev.get("direction", "")
        self.method = ev.get("method", "")
        self.url = ev.get("url", "")
        self.path = ev.get("path", "")
        self.headers = ev.get("headers", {}) or {}
        self.body = ev.get("body", "")
        self.status = ev.get("status", 0)
        self.msg_kind = ev.get("msg_kind", "")
        self.sql = ev.get("sql", "")
        self.cmd = ev.get("cmd", "")
        self.args = ev.get("args", []) or []
        self.row = ev.get("row")
        self.text = ev.get("text", "")
        self.ctx = _ctx_for(self.id)

    @property
    def json(self):
        try:
            return json.loads(self.body) if self.body else None
        except Exception:
            return None

    @property
    def is_select(self):
        s = (self.sql or "").lstrip().lower()
        return s.startswith("select") or s.startswith("with")

    def header(self, name):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v[0] if isinstance(v, list) else v
        return None

    def has_column(self, name):
        return self.row is not None and name in self.text


_BUILTINS = {
    "state": STATE, "random": random, "time": time, "json": json,
    "drop": drop, "delay": delay, "edit": edit, "respond": respond,
    "hold": hold, "record": record, "log": log,
}


def load_user():
    """(Re)load the user script into a fresh namespace that keeps the shared STATE object."""
    global USER
    with open(USER_PATH, "r") as f:
        src = f.read()
    ns = dict(_BUILTINS)
    ns["__name__"] = "ntcept_script"
    ns["__file__"] = USER_PATH
    exec(compile(src, USER_PATH, "exec"), ns)
    USER = ns


def dispatch(ev):
    if USER is None:
        return None
    hook = ev.get("hook", "")
    fn = USER.get(hook) or USER.get("handle")
    if fn is None:
        return None
    return fn(Msg(ev))


def main():
    try:
        load_user()
    except Exception:
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({"seq": 0, "ok": False, "error": "load failed"}), flush=True)
        # Keep running so a reload can fix it; every event fails open until then.
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        seq = req.get("seq", 0)
        if req.get("t") == "cmd":
            reply = {"seq": seq, "ok": True}
            try:
                cmd = req.get("cmd")
                if cmd == "reset":
                    STATE.clear()
                    CTX.clear()
                    CTX_ORDER.clear()
                    load_user()
                elif cmd == "reload":
                    load_user()
                # ping: nothing to do
            except Exception:
                traceback.print_exc(file=sys.stderr)
                reply["ok"] = False
                reply["error"] = "reload failed"
            print(json.dumps(reply), flush=True)
            continue
        # An event.
        _logbuf.clear()
        try:
            verdict = dispatch(req) or {"action": "pass"}
            if not isinstance(verdict, dict):
                verdict = {"action": "pass"}
        except Exception:
            traceback.print_exc(file=sys.stderr)
            verdict = {"action": "pass"}  # fail open
        verdict["seq"] = seq
        if _logbuf:
            verdict["logs"] = list(_logbuf)
        try:
            print(json.dumps(verdict), flush=True)
        except Exception:
            print(json.dumps({"seq": seq, "action": "pass"}), flush=True)
        if req.get("end"):
            CTX.pop(req.get("id", ""), None)


if __name__ == "__main__":
    main()
