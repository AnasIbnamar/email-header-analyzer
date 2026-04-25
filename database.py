import sqlite3
import json
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")


def init_db():
    """Create the scans table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at  TEXT NOT NULL,
            subject     TEXT,
            from_addr   TEXT,
            risk_score  INTEGER,
            verdict     TEXT,
            spf_status  TEXT,
            dmarc_policy TEXT,
            dkim_present INTEGER,
            warnings     INTEGER,
            malicious_ips INTEGER,
            report_json  TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(report):
    """Save a completed analysis report to the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    score = report["risk_score"]

    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    malicious_ips = sum(
        1 for g in report["geo"]
        if g.get("abuse", {}).get("verdict") == "malicious"
    )

    c.execute("""
        INSERT INTO scans
        (scanned_at, subject, from_addr, risk_score, verdict,
         spf_status, dmarc_policy, dkim_present, warnings, malicious_ips, report_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        report["parsed"].get("subject", ""),
        report["parsed"].get("from", ""),
        score,
        verdict,
        report["spf"].get("verdict", ""),
        report["dmarc"].get("policy", ""),
        1 if report["dkim"]["present"] else 0,
        len(report["spoofing_warnings"]),
        malicious_ips,
        json.dumps(report, default=str)
    ))

    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_all_scans():
    """Return all scans ordered by most recent first."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT id, scanned_at, subject, from_addr, risk_score,
               verdict, malicious_ips, warnings
        FROM scans
        ORDER BY id DESC
        LIMIT 100
    """)
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id):
    """Return a single scan's full report JSON by ID."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT report_json FROM scans WHERE id = ?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return json.loads(row[0])
    return None


def delete_scan(scan_id):
    """Delete a scan by ID."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()