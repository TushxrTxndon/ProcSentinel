"""SQLite log of alerts and user actions."""
import json
import os
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, ts REAL, pid INTEGER, name TEXT, type TEXT, severity TEXT,
  layers TEXT, metrics TEXT, snapshot TEXT, title TEXT, concept TEXT,
  explanation TEXT, suggestion TEXT, actions TEXT, ai_explanation TEXT, ai_status TEXT
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY, ts REAL, pid INTEGER, name TEXT, action TEXT, value TEXT,
  ok INTEGER, message TEXT, alert_id INTEGER
);
"""
JSON_COLS = ("layers", "metrics", "snapshot", "actions")


class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()

    def add_alert(self, a):
        with self.lock, self.db:
            cur = self.db.execute(
                "INSERT INTO alerts (ts,pid,name,type,severity,layers,metrics,snapshot,title,concept,explanation,"
                "suggestion,actions,ai_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a["ts"], a["pid"], a["name"], a["type"], a["severity"], json.dumps(a["layers"]),
                 json.dumps(a["metrics"], default=str), json.dumps(a["snapshot"]), a["title"], a["concept"],
                 a["explanation"], a["suggestion"], json.dumps(a["actions"]), a.get("ai_status")))
            return cur.lastrowid

    def update_layers(self, alert_id, layers, metrics):
        with self.lock, self.db:
            self.db.execute("UPDATE alerts SET layers=?, metrics=? WHERE id=?",
                            (json.dumps(layers), json.dumps(metrics, default=str), alert_id))

    def set_ai(self, alert_id, text, status):
        with self.lock, self.db:
            self.db.execute("UPDATE alerts SET ai_explanation=?, ai_status=? WHERE id=?", (text, status, alert_id))

    def add_action(self, ts, pid, name, action, value, ok, message, alert_id):
        with self.lock, self.db:
            self.db.execute("INSERT INTO actions (ts,pid,name,action,value,ok,message,alert_id) VALUES (?,?,?,?,?,?,?,?)",
                            (ts, pid, name, action, None if value is None else str(value), int(ok), message, alert_id))

    def alerts(self, limit=50):
        with self.lock:
            rows = self.db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for c in JSON_COLS:
                d[c] = json.loads(d[c]) if d[c] else None
            out.append(d)
        return out

    def actions(self, limit=50):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,))]

    def clear(self):
        with self.lock, self.db:
            self.db.execute("DELETE FROM alerts")
            self.db.execute("DELETE FROM actions")
