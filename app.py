from flask import Flask, render_template, redirect, jsonify, request, session, url_for
import sqlite3
from datetime import datetime

app = Flask(__name__)

app.secret_key = "cloud_security_monitor_2026"

DB = "database.db"

# Initialize database tables
def init_db():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    
    # Create packets table if not exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            packet_size INTEGER,
            icmp_type INTEGER,
            time TEXT
        )
    """)
    
    # Create blocked_ips table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            reason TEXT,
            blocked_time TEXT
        )
    """)
    
    conn.commit()
    conn.close()

init_db()

# ---------------- HOME ---------------- #

@app.route("/")
def home():
    # Clear any existing session first
    session.clear()
    
    if session.get("logged_in"):
        return redirect("/dashboard")
    
    return render_template("login.html")

# ---------------- LOGIN ---------------- #

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username == "admin" and password == "admin123":
        session["logged_in"] = True
        session["username"] = username
        return redirect("/dashboard")

    return render_template(
        "login.html",
        error="Invalid Username or Password"
    )

# ---------------- LOGOUT ---------------- #

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- DASHBOARD ---------------- #

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect("/")

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            source_ip,
            destination_ip,
            protocol,
            packet_size,
            icmp_type,
            time
        FROM packets
        ORDER BY id DESC
        LIMIT 100
    """)

    packets = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM packets")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_time DESC")
    blocked = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        packets=packets,
        total=total,
        blocked=blocked,
        username=session.get("username")
    )

# ---------------- LIVE API ---------------- #

@app.route("/api/packets")
def api_packets():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get suspicious IPs (threshold: 50 packets)
    cursor.execute("""
        SELECT source_ip, COUNT(*) as count
        FROM packets
        GROUP BY source_ip
        HAVING COUNT(*) >= 50
    """)
    suspicious_ips = {row['source_ip']: row['count'] for row in cursor.fetchall()}

    # Get blocked IPs
    cursor.execute("SELECT ip_address FROM blocked_ips")
    blocked_ips = {row[0] for row in cursor.fetchall()}

    # Get packet counts per IP
    cursor.execute("""
        SELECT source_ip, COUNT(*) as count
        FROM packets
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 10
    """)
    top_ips = [dict(row) for row in cursor.fetchall()]

    # Get recent packets
    cursor.execute("""
        SELECT
            id,
            source_ip,
            destination_ip,
            protocol,
            packet_size,
            icmp_type,
            time
        FROM packets
        ORDER BY id DESC
        LIMIT 100
    """)

    packets = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM packets")
    total = cursor.fetchone()[0]

    conn.close()

    return jsonify({
        "total": total,
        "packets": [dict(packet) for packet in packets],
        "suspicious": suspicious_ips,
        "blocked": list(blocked_ips),
        "top_ips": top_ips
    })

# ---------------- BLOCK IP ---------------- #

@app.route("/api/block", methods=["POST"])
def block_ip():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    ip_address = data.get("ip")
    
    if not ip_address:
        return jsonify({"error": "IP address required"}), 400

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    # Check if already blocked
    cursor.execute("SELECT * FROM blocked_ips WHERE ip_address=?", (ip_address,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "IP already blocked"}), 400

    blocked_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")

    cursor.execute("""
        INSERT INTO blocked_ips (ip_address, reason, blocked_time)
        VALUES (?, ?, ?)
    """, (ip_address, "Manual Block", blocked_time))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"IP {ip_address} blocked"})

# ---------------- UNBLOCK IP ---------------- #

@app.route("/api/unblock", methods=["POST"])
def unblock_ip():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    ip_address = data.get("ip")

    if not ip_address:
        return jsonify({"error": "IP address required"}), 400

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM blocked_ips WHERE ip_address=?", (ip_address,))
    rows = cursor.rowcount

    conn.commit()
    conn.close()

    if rows > 0:
        return jsonify({"success": True, "message": f"IP {ip_address} unblocked"})
    else:
        return jsonify({"error": "IP not found in blocked list"}), 404

# ---------------- CLEAR LOGS ---------------- #

@app.route("/clear")
def clear_logs():
    if not session.get("logged_in"):
        return redirect("/")

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM packets")
    conn.commit()
    conn.close()

    return redirect("/dashboard")

# ---------------- RUN ---------------- #

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
