from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3

app=Flask(__name__)
CORS(app)
DB="patch_manager.db"

def db():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    return c

def init_db():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS assets(
      id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT NOT NULL,
      ip_address TEXT, operating_system TEXT, owner TEXT,
      environment TEXT DEFAULT 'Production');
    CREATE TABLE IF NOT EXISTS software(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      version TEXT NOT NULL, vendor TEXT, asset_id INTEGER);
    CREATE TABLE IF NOT EXISTS vulnerabilities(
      id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL, severity TEXT NOT NULL, cvss REAL DEFAULT 0,
      affected_software TEXT, status TEXT DEFAULT 'Open');
    CREATE TABLE IF NOT EXISTS patches(
      id INTEGER PRIMARY KEY AUTOINCREMENT, patch_name TEXT NOT NULL,
      version TEXT, vendor TEXT, cve_id TEXT, release_date TEXT,
      status TEXT DEFAULT 'Available');
    CREATE TABLE IF NOT EXISTS remediation(
      id INTEGER PRIMARY KEY AUTOINCREMENT, vulnerability_id INTEGER,
      asset_id INTEGER, assigned_to TEXT, due_date TEXT,
      status TEXT DEFAULT 'Open', notes TEXT);
    """)
    if c.execute("SELECT COUNT(*) FROM assets").fetchone()[0]==0:
        c.executemany("INSERT INTO assets(hostname,ip_address,operating_system,owner,environment) VALUES(?,?,?,?,?)",[
          ("WEB-SERVER-01","192.168.1.20","Ubuntu 22.04","IT Team","Production"),
          ("WIN-CLIENT-07","192.168.1.45","Windows 11","HR Team","Corporate"),
          ("DB-SERVER-01","192.168.1.30","Ubuntu 24.04","DB Team","Production")])
        c.executemany("INSERT INTO software(name,version,vendor,asset_id) VALUES(?,?,?,?)",[
          ("OpenSSL","3.0.2","OpenSSL",1),("Apache HTTP Server","2.4.52","Apache",1),
          ("7-Zip","24.06","7-Zip",2),("PostgreSQL","16.3","PostgreSQL",3)])
        c.executemany("INSERT INTO vulnerabilities(cve_id,title,severity,cvss,affected_software,status) VALUES(?,?,?,?,?,?)",[
          ("CVE-2025-0001","Example OpenSSL vulnerability","Critical",9.8,"OpenSSL 3.0.2","Open"),
          ("CVE-2025-0002","Example Apache vulnerability","High",8.1,"Apache 2.4.52","Open"),
          ("CVE-2025-0003","Example 7-Zip vulnerability","Medium",6.5,"7-Zip 24.06","Patched")])
        c.executemany("INSERT INTO patches(patch_name,version,vendor,cve_id,release_date,status) VALUES(?,?,?,?,?,?)",[
          ("OpenSSL Security Update","3.0.15","OpenSSL","CVE-2025-0001","2025-02-10","Available"),
          ("Apache Security Update","2.4.63","Apache","CVE-2025-0002","2025-03-01","Available"),
          ("7-Zip Security Update","24.07","7-Zip","CVE-2025-0003","2025-01-20","Installed")])
    c.commit(); c.close()

def allrows(x): return [dict(r) for r in x]

@app.get("/")
def home(): return render_template("index.html")

@app.get("/api/dashboard")
def dashboard():
    c=db()
    d={
      "assets":c.execute("SELECT COUNT(*) FROM assets").fetchone()[0],
      "software":c.execute("SELECT COUNT(*) FROM software").fetchone()[0],
      "vulnerabilities":c.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0],
      "critical":c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity='Critical' AND status!='Patched'").fetchone()[0],
      "open":c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status='Open'").fetchone()[0],
      "patched":c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status='Patched'").fetchone()[0],
      "patches":c.execute("SELECT COUNT(*) FROM patches").fetchone()[0]}
    c.close()
    d["compliance"]=round(d["patched"]/d["vulnerabilities"]*100,1) if d["vulnerabilities"] else 100
    return jsonify(d)

@app.route("/api/assets",methods=["GET","POST"])
def assets():
    c=db()
    if request.method=="POST":
        d=request.json
        cur=c.execute("INSERT INTO assets(hostname,ip_address,operating_system,owner,environment) VALUES(?,?,?,?,?)",
          (d["hostname"],d.get("ip_address",""),d.get("operating_system",""),d.get("owner",""),d.get("environment","Production")))
        c.commit(); r=c.execute("SELECT * FROM assets WHERE id=?",(cur.lastrowid,)).fetchone(); c.close()
        return jsonify(dict(r)),201
    r=allrows(c.execute("SELECT * FROM assets ORDER BY id DESC")); c.close(); return jsonify(r)

@app.route("/api/software",methods=["GET","POST"])
def software():
    c=db()
    if request.method=="POST":
        d=request.json
        cur=c.execute("INSERT INTO software(name,version,vendor,asset_id) VALUES(?,?,?,?)",
          (d["name"],d["version"],d.get("vendor",""),d.get("asset_id")))
        c.commit(); r=c.execute("SELECT * FROM software WHERE id=?",(cur.lastrowid,)).fetchone(); c.close()
        return jsonify(dict(r)),201
    r=allrows(c.execute("SELECT software.*,assets.hostname FROM software LEFT JOIN assets ON assets.id=software.asset_id ORDER BY software.id DESC"))
    c.close(); return jsonify(r)

@app.route("/api/vulnerabilities",methods=["GET","POST","PATCH"])
def vulnerabilities():
    c=db()
    if request.method=="POST":
        d=request.json
        try:
            cur=c.execute("INSERT INTO vulnerabilities(cve_id,title,severity,cvss,affected_software,status) VALUES(?,?,?,?,?,?)",
              (d["cve_id"],d["title"],d["severity"],d.get("cvss",0),d.get("affected_software",""),d.get("status","Open")))
            c.commit()
        except sqlite3.IntegrityError:
            c.close(); return jsonify({"error":"CVE already exists"}),409
        r=c.execute("SELECT * FROM vulnerabilities WHERE id=?",(cur.lastrowid,)).fetchone(); c.close(); return jsonify(dict(r)),201
    if request.method=="PATCH":
        d=request.json; c.execute("UPDATE vulnerabilities SET status=? WHERE id=?",(d["status"],d["id"])); c.commit()
        r=c.execute("SELECT * FROM vulnerabilities WHERE id=?",(d["id"],)).fetchone(); c.close(); return jsonify(dict(r))
    r=allrows(c.execute("SELECT * FROM vulnerabilities ORDER BY cvss DESC")); c.close(); return jsonify(r)

@app.route("/api/patches",methods=["GET","POST","PATCH"])
def patches():
    c=db()
    if request.method=="POST":
        d=request.json
        cur=c.execute("INSERT INTO patches(patch_name,version,vendor,cve_id,release_date,status) VALUES(?,?,?,?,?,?)",
          (d["patch_name"],d.get("version",""),d.get("vendor",""),d.get("cve_id",""),d.get("release_date",""),d.get("status","Available")))
        c.commit(); r=c.execute("SELECT * FROM patches WHERE id=?",(cur.lastrowid,)).fetchone(); c.close(); return jsonify(dict(r)),201
    if request.method=="PATCH":
        d=request.json; c.execute("UPDATE patches SET status=? WHERE id=?",(d["status"],d["id"])); c.commit()
        r=c.execute("SELECT * FROM patches WHERE id=?",(d["id"],)).fetchone(); c.close(); return jsonify(dict(r))
    r=allrows(c.execute("SELECT * FROM patches ORDER BY id DESC")); c.close(); return jsonify(r)

@app.route("/api/remediation",methods=["GET","POST","PATCH"])
def remediation():
    c=db()
    if request.method=="POST":
        d=request.json
        cur=c.execute("INSERT INTO remediation(vulnerability_id,asset_id,assigned_to,due_date,status,notes) VALUES(?,?,?,?,?,?)",
          (d.get("vulnerability_id"),d.get("asset_id"),d.get("assigned_to",""),d.get("due_date",""),d.get("status","Open"),d.get("notes","")))
        c.commit(); r=c.execute("SELECT * FROM remediation WHERE id=?",(cur.lastrowid,)).fetchone(); c.close(); return jsonify(dict(r)),201
    if request.method=="PATCH":
        d=request.json; c.execute("UPDATE remediation SET status=? WHERE id=?",(d["status"],d["id"])); c.commit()
        r=c.execute("SELECT * FROM remediation WHERE id=?",(d["id"],)).fetchone(); c.close(); return jsonify(dict(r))
    r=allrows(c.execute("""SELECT remediation.*,vulnerabilities.cve_id,assets.hostname
      FROM remediation LEFT JOIN vulnerabilities ON vulnerabilities.id=remediation.vulnerability_id
      LEFT JOIN assets ON assets.id=remediation.asset_id ORDER BY remediation.id DESC"""))
    c.close(); return jsonify(r)

if __name__=="__main__":
    init_db()
    app.run(debug=True)
