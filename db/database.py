import sqlite3
import json
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'webguard.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Tabela com 6 colunas incluindo technologies
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            total_vulns INTEGER,
            vuln_details TEXT,
            technologies TEXT
        )
    ''')
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN technologies TEXT")
    except sqlite3.OperationalError:
        pass 
    conn.commit()
    conn.close()

def save_scan(target_url, vulns, techs=[]):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    date_now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    vulns_json = json.dumps(vulns, ensure_ascii=False)
    techs_json = json.dumps(techs, ensure_ascii=False)
    
    cursor.execute('''
        INSERT INTO scans (target_url, scan_date, total_vulns, vuln_details, technologies)
        VALUES (?, ?, ?, ?, ?)
    ''', (target_url, date_now, len(vulns), vulns_json, techs_json))
    
    conn.commit()
    conn.close()

def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Retorna as 6 colunas
    cursor.execute("SELECT id, target_url, scan_date, total_vulns, vuln_details, technologies FROM scans ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Retorna as 6 colunas
    cursor.execute("SELECT id, target_url, scan_date, total_vulns, vuln_details, technologies FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return row