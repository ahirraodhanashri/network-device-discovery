"""SQLite storage for scans, discovered devices and detected anomalies."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent / "network_discovery.db"


def db_path():
    return Path(os.environ.get("NETDISCOVERY_DB", DEFAULT_DB))


@contextmanager
def connect():
    """Open a connection, commit on success, always close (sqlite3's own `with` never closes)."""
    con = sqlite3.connect(db_path())
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _ensure_columns(con, table, columns):
    existing = {row["name"] for row in con.execute(f"PRAGMA table_info({table})")}
    for name, ddl in columns.items():
        if name not in existing:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def init_db():
    with connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL, subnet TEXT NOT NULL,
            method TEXT NOT NULL, status TEXT NOT NULL,
            device_count INTEGER NOT NULL DEFAULT 0, error TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL, ip TEXT NOT NULL, mac TEXT,
            hostname TEXT, vendor TEXT, method TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)""")
        con.execute("""CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL,
            ip TEXT, message TEXT NOT NULL, details TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)""")
        # Upgrade databases created by the first version of the project.
        _ensure_columns(con, "scans", {"gateway_ip": "TEXT", "is_demo": "INTEGER NOT NULL DEFAULT 0",
                                       "demo_variant": "TEXT"})
        _ensure_columns(con, "devices", {"rtt_ms": "REAL", "ttl": "INTEGER", "os_hint": "TEXT",
                                         "open_ports": "TEXT", "is_gateway": "INTEGER NOT NULL DEFAULT 0"})


def save_scan(subnet, method_label, status, result=None, error=None, demo_variant=None):
    result = result or {"devices": [], "anomalies": [], "gateway_ip": None}
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with connect() as con:
        cur = con.execute(
            "INSERT INTO scans(started_at,subnet,method,status,device_count,error,gateway_ip,is_demo,demo_variant)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (started, subnet, method_label, status, len(result["devices"]), error,
             result.get("gateway_ip"), 1 if demo_variant else 0, demo_variant))
        scan_id = cur.lastrowid
        con.executemany(
            "INSERT INTO devices(scan_id,ip,mac,hostname,vendor,method,rtt_ms,ttl,os_hint,open_ports,is_gateway)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            [(scan_id, d["ip"], d.get("mac"), d.get("hostname"), d.get("vendor"), "+".join(d["methods"]),
              d.get("rtt_ms"), d.get("ttl"), d.get("os_hint"), json.dumps(d.get("open_ports", [])),
              1 if d.get("is_gateway") else 0) for d in result["devices"]])
        con.executemany(
            "INSERT INTO anomalies(scan_id,type,severity,ip,message,details) VALUES(?,?,?,?,?,?)",
            [(scan_id, a["type"], a["severity"], a["ip"], a["message"], json.dumps(a.get("details", {})))
             for a in result.get("anomalies", [])])
    return scan_id


def _device_row(row):
    d = dict(row)
    d["methods"] = d.pop("method").split("+")
    d["open_ports"] = json.loads(d["open_ports"]) if d.get("open_ports") else []
    d["is_gateway"] = bool(d["is_gateway"])
    d.pop("id", None)
    d.pop("scan_id", None)
    return d


def _ip_key(ip):
    return tuple(int(p) for p in ip.split("."))


def get_devices(scan_id, con=None):
    def fetch(c):
        rows = c.execute("SELECT * FROM devices WHERE scan_id=?", (scan_id,)).fetchall()
        return sorted((_device_row(r) for r in rows), key=lambda d: _ip_key(d["ip"]))
    if con is not None:
        return fetch(con)
    with connect() as c:
        return fetch(c)


def get_scan(scan_id):
    with connect() as con:
        scan = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return None
        result = dict(scan)
        result["is_demo"] = bool(result["is_demo"])
        result["devices"] = get_devices(scan_id, con)
        anomalies = con.execute("SELECT type,severity,ip,message,details FROM anomalies WHERE scan_id=? ORDER BY id",
                                (scan_id,)).fetchall()
        result["anomalies"] = [{**dict(a), "details": json.loads(a["details"] or "{}")} for a in anomalies]
    return result


def list_scans(limit=100):
    with connect() as con:
        rows = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    scans = [dict(r) for r in rows]
    for s in scans:
        s["is_demo"] = bool(s["is_demo"])
    return scans


def previous_scan_id(subnet, is_demo, before_id):
    """Latest completed scan of the same subnet and same data source (real vs demo)."""
    with connect() as con:
        row = con.execute(
            "SELECT id FROM scans WHERE subnet=? AND is_demo=? AND status='completed' AND id<? "
            "ORDER BY id DESC LIMIT 1", (subnet, 1 if is_demo else 0, before_id)).fetchone()
    return row["id"] if row else None


def delete_scan(scan_id):
    with connect() as con:
        con.execute("DELETE FROM devices WHERE scan_id=?", (scan_id,))
        con.execute("DELETE FROM anomalies WHERE scan_id=?", (scan_id,))
        cur = con.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        return cur.rowcount > 0
