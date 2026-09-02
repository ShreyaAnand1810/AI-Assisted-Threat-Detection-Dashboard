import os
import sqlite3
import pandas as pd
import plotly.express as px
import csv
from io import StringIO
import sqlite3
from flask import request, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from flask import Response
import csv
from datetime import datetime
from database.scan import get_scans_paginated
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph
from auth_decorators import admin_required
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch
from reportlab.lib import colors
from flask import jsonify
from database.scan import search_scans
from auth import User, users
import google.generativeai as genai
from database.scan import save_scan as db_save_scan
from tools.nmap_scan import run_nmap_scan
from tools.wireshark_parser import read_pcap
from tools.penetration import get_security_report
from database.user import *
create_user_table()
create_default_admin()

def add_user(username,password,role):

    conn=get_connection()

    cursor=conn.cursor()

    cursor.execute("""

    INSERT INTO users(

        username,

        password,

        role

    )

    VALUES(?,?,?)

    """,(username,password,role))

    conn.commit()

    conn.close()

def get_users():

    conn=get_connection()

    cursor=conn.cursor()

    cursor.execute("""

    SELECT *

    FROM users

    ORDER BY username

    """)

    rows=cursor.fetchall()

    conn.close()

    return rows
def delete_user(user_id):

    conn=get_connection()

    cursor=conn.cursor()

    cursor.execute(

        "DELETE FROM users WHERE id=?",

        (user_id,)

    )

    conn.commit()

    conn.close()

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    flash
)

from werkzeug.utils import secure_filename

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

import config

# -----------------------------
# Authentication
# -----------------------------

from auth import User, users

# -----------------------------
# Machine Learning
# -----------------------------

from ml.feature_extractor import extract_features
from ml.predictor import ThreatPredictor

predictor_instance = ThreatPredictor()
# -----------------------------
# Database
# -----------------------------

from database.scan import (

    create_table,

    save_scan,

    get_all_scans,

    delete_scan,

    dashboard_stats,

    scans_per_day,

    risk_distribution,

    recent_scans,

    top_extensions,

    monthly_scans,

    detection_rate,

    security_score

)
# ======================================
# Flask Configuration
# ======================================

app = Flask(__name__)


import os

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")

create_table()

app.config["SECRET_KEY"] = config.SECRET_KEY

app.config["UPLOAD_FOLDER"] = "uploads"

UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'sys', 'drv', 'com',          # Executables & Drivers
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', # Documents
    'zip', 'rar', '7z', 'tar', 'gz',            # Archives
    'csv', 'json', 'txt',                       # Data & Logs
    'pcap', 'pcapng', 'png', 'csv'                            # Packet Captures
}

def allowed_file(filename: str) -> bool:
    """Check if uploaded file extension is permitted."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def predict(features_or_dict):
    """
    Invokes Singleton ThreatPredictor to analyze features or raw file parameters.
    """
    try:
        return predictor_instance.predict(features_or_dict)
    except Exception as e:
        return {
            "status": "error",
            "prediction": "Error",
            "confidence": 0.0,
            "risk_level": "Unknown",
            "recommendation": f"Model inference error: {str(e)}"
        }

def save_scan(filename, features, result):
    """
    Persists threat scan result into SQLite database.
    """
    from database.scan import add_scan
    try:
        add_scan(
            filename=filename,
            features=features,
            prediction=result.get("prediction", "Unknown"),
            confidence=result.get("confidence", 0.0),
            risk=result.get("risk_level", result.get("risk", "Low")),
            recommendation=result.get("recommendation", "")
        )
    except Exception as db_err:
        print(f"Warning: Scan DB record insertion failed: {db_err}")

@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    Automated File Upload & Threat Prediction Endpoint.
    Returns structured JSON with threat classification, confidence %, risk level, and metadata.
    """
    # 1. Direct JSON Payload Input
    if request.is_json:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "Empty JSON payload."}), 400
        
        res = predict(data)
        if res.get("status") == "error":
            return jsonify({"success": False, "error": res.get("recommendation", "Prediction failed")}), 400

        return jsonify({
            "success": True,
            "prediction": res.get("prediction"),
            "threat_type": res.get("threat_type", "Unknown"),
            "confidence": res.get("confidence"),
            "risk_level": res.get("risk_level", res.get("risk")),
            "timestamp": res.get("timestamp"),
            "model": res.get("model_used"),
            "processing_time_ms": res.get("processing_time_ms"),
            "recommendation": res.get("recommendation")
        }), 200

    # 2. File Upload via Multipart/form-data
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file parameter found in request."}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"success": False, "error": "No file selected for upload."}), 400

    if not allowed_file(file.filename):
        return jsonify({
            "success": False,
            "error": f"Unsupported file type. Allowed formats: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        }), 415

    # Path traversal protection
    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({"success": False, "error": "Invalid filename."}), 400

    temp_filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    try:
        file.save(temp_filepath)

        # Check empty file
        if os.path.getsize(temp_filepath) == 0:
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)
            return jsonify({"success": False, "error": "Uploaded file is empty (0 bytes)."}), 400

        # Run Feature Extraction & ML Prediction
        features = extract_features(temp_filepath)
        pred_result = predict(features)

        if pred_result.get("status") == "error":
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)
            return jsonify({"success": False, "error": pred_result.get("recommendation")}), 500

        # Persist scan result in database
        try:
            save_scan(filename, features, pred_result)
        except Exception as db_err:
            print(f"Warning: Scan DB save failed: {db_err}")

        # Secure Cleanup of temporary file
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)

        return jsonify({
            "success": True,
            "prediction": pred_result.get("prediction"),
            "threat_type": pred_result.get("threat_type", "Unknown"),
            "confidence": pred_result.get("confidence"),
            "risk_level": pred_result.get("risk_level", pred_result.get("risk")),
            "timestamp": pred_result.get("timestamp"),
            "model": pred_result.get("model_used"),
            "processing_time_ms": pred_result.get("processing_time_ms"),
            "recommendation": pred_result.get("recommendation")
        }), 200

    except Exception as e:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        return jsonify({"success": False, "error": f"Internal server error: {str(e)}"}), 500


# ======================================
# Flask Login Configuration
# ======================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect("database/threat.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users WHERE username=?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return User(user["username"], user["role"])

    return None
def allowed_file(filename):

    return "." in filename and \
        filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():

    return redirect(url_for("login"))

@app.route("/users")
@login_required
@admin_required
def users_page():

    all_users = get_users()

    return render_template(
        "users.html",
        users=all_users
    )

@app.route("/delete_user/<int:id>")
@login_required
@admin_required
def remove_user(id):

    delete_user(id)

    return redirect(url_for("users"))


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database/threat.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):

            login_user(
                User(
                    user["username"],
                    user["role"]
                )
            )

            return redirect(url_for("dashboard"))

        flash("Invalid Username or Password")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():

    stats = dashboard_stats()

    daily = scans_per_day()

    risk = risk_distribution()

    recent = recent_scans()

    extensions = top_extensions()

    months = monthly_scans()

    rate = detection_rate()

    score = security_score()

    # ----------------------------
    # Daily Scan Chart
    # ----------------------------

    if len(daily) > 0:

        df = pd.DataFrame(
            daily,
            columns=["Date", "Scans"]
        )

        line = px.line(
            df,
            x="Date",
            y="Scans",
            markers=True,
            title="Daily Scan Activity"
        )

    else:

        line = px.line(
            pd.DataFrame({
                "Date": [],
                "Scans": []
            }),
            x="Date",
            y="Scans"
        )

    # ----------------------------
    # Threat Distribution Pie Chart
    # ----------------------------

    pie = px.pie(

        names=["Safe", "Malicious"],

        values=[
            stats["safe"],
            stats["malicious"]
        ],

        title="Threat Distribution"

    )

    # ----------------------------
    # Risk Level Chart
    # ----------------------------

    if len(risk) > 0:

        risk_df = pd.DataFrame(

            risk,

            columns=["Risk", "Count"]

        )

        bar = px.bar(

            risk_df,

            x="Risk",

            y="Count",

            title="Risk Levels"

        )

    else:

        bar = px.bar(

            pd.DataFrame({

                "Risk": [],

                "Count": []

            }),

            x="Risk",

            y="Count"

        )

      # ----------------------------
    # Convert Charts to HTML
    # ----------------------------

    line = line.to_html(full_html=False)
    pie = pie.to_html(full_html=False)
    bar = bar.to_html(full_html=False)

    # ----------------------------
    # Top File Extensions Chart
    # ----------------------------

    if len(extensions) > 0:

        ext_df = pd.DataFrame(
            extensions,
            columns=["Extension", "Count"]
        )

        extension_chart = px.bar(
            ext_df,
            x="Extension",
            y="Count",
            title="Top File Extensions"
        )

    else:

        extension_chart = px.bar(
            pd.DataFrame({
                "Extension": [],
                "Count": []
            }),
            x="Extension",
            y="Count"
        )

    extension_chart.update_layout(template="plotly_dark")

    extension_chart = extension_chart.to_html(full_html=False)

    # ----------------------------
    # Monthly Scan Trend
    # ----------------------------

    if len(months) > 0:

        month_df = pd.DataFrame(
            months,
            columns=["Month", "Scans"]
        )

        monthly_chart = px.line(
            month_df,
            x="Month",
            y="Scans",
            markers=True,
            title="Monthly Scan Trend"
        )

    else:

        monthly_chart = px.line(
            pd.DataFrame({
                "Month": [],
                "Scans": []
            }),
            x="Month",
            y="Scans"
        )

    monthly_chart.update_layout(template="plotly_dark")

    monthly_chart = monthly_chart.to_html(full_html=False)

    # ----------------------------
    # Render Dashboard
    # ----------------------------

    return render_template(

        "dashboard.html",

        user=current_user.id,

        stats=stats,

        line=line,

        pie=pie,

        bar=bar,

        recent=recent,

        rate=rate,

        score=score,

        extension_chart=extension_chart,

        monthly_chart=monthly_chart

    )  
from flask import jsonify

@app.route("/api/dashboard")
@login_required
def dashboard_api():

    stats = dashboard_stats()

    return jsonify({
        "total": stats["total"],
        "safe": stats["safe"],
        "malicious": stats["malicious"],
        "critical": stats["critical"],
        "last_scan": stats["last_scan"]
    })

@app.route("/reports")
@login_required
def reports():

    stats = dashboard_stats()

    daily = scans_per_day()

    risk = risk_distribution()

    recent = recent_scans()

    rate = detection_rate()

    score = security_score()

    # ----------------------------
    # Daily Scan Chart
    # ----------------------------

    if daily:

        df = pd.DataFrame(
            daily,
            columns=["Date", "Scans"]
        )

        line = px.line(

            df,

            x="Date",

            y="Scans",

            markers=True,

            title="Daily Scan Activity"

        )

    else:

        line = px.line(

            pd.DataFrame({

                "Date": [],

                "Scans": []

            }),

            x="Date",

            y="Scans"

        )

    line.update_layout(template="plotly_dark")

    line = line.to_html(full_html=False)

    # ----------------------------
    # Threat Distribution
    # ----------------------------

    pie = px.pie(

        names=["Safe", "Malicious"],

        values=[

            stats["safe"],

            stats["malicious"]

        ],

        title="Threat Distribution"

    )

    pie.update_layout(template="plotly_dark")

    pie = pie.to_html(full_html=False)

    # ----------------------------
    # Render Reports Page
    # ----------------------------

    return render_template(

        "reports.html",

        user=current_user.id,

        stats=stats,

        line=line,

        pie=pie,

        recent=recent,

        rate=rate,

        score=score

    )

@app.route("/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    per_page = 10

    # ✅ New filters
    search = request.args.get("search", "")
    risk = request.args.get("risk", "")

    # ✅ Updated call with search + risk
    scans, total = get_scans_paginated(
        page,
        per_page,
        search,
        risk
    )

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "history.html",
        scans=scans,
        page=page,
        total_pages=total_pages,
        search=search,
        risk=risk
    )

    return render_template(
    "history.html",
    scans=scans,
    page=page,
    total_pages=total_pages
)

@app.route("/remove_scan/<int:scan_id>")
@login_required
def remove_scan(scan_id):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM scans WHERE id=?",
        (scan_id,)
    )

    conn.commit()
    conn.close()

    flash("Scan deleted successfully.", "success")

    return redirect(url_for("history"))

@app.route("/delete/<int:id>")
@login_required
@admin_required
def delete(id):

    delete_scan(id)

    return redirect(url_for("history"))

    # ----------------------------
    # Pie Chart
    # ----------------------------

    pie = px.pie(

        names=["Safe","Malicious"],

        values=[

            stats["safe"],

            stats["malicious"]

        ],

        title="Threat Distribution"

    )

    # ----------------------------
    # Risk Chart
    # ----------------------------

    if len(risk) > 0:

        risk_df = pd.DataFrame(

            risk,

            columns=["Risk","Count"]

        )

        bar = px.bar(

            risk_df,

            x="Risk",

            y="Count",

            title="Risk Levels"

        )

    else:

        bar = px.bar(

            pd.DataFrame({

                "Risk":[],

                "Count":[]

            }),

            x="Risk",

            y="Count"

        )

    return render_template(

        "dashboard.html",

        stats=stats,

        line=line.to_html(full_html=False),

        pie=pie.to_html(full_html=False),

        bar=bar.to_html(full_html=False),

        recent=recent,

        user=current_user.id

    )
@app.route("/security_tools")
@login_required
def security_tools():
    return render_template("security_tools.html")


@app.route("/run_nmap", methods=["POST"])
@login_required
def run_nmap():

    target = request.form["target"]

    result = run_nmap_scan(target)

    return jsonify(result)


@app.route("/read_pcap", methods=["POST"])
@login_required
def read_capture():

    if "pcap_file" not in request.files:
        flash("Please upload a PCAP file.", "danger")
        return redirect(url_for("security_tools"))

    file = request.files["pcap_file"]

    result = read_pcap(file)

    if result.get("status") == "error":
        flash(result["message"], "danger")
        return redirect(url_for("security_tools"))

    return render_template(
        "pcap_result.html",
        result=result
    )

@app.route("/penetration_report")
@login_required
def penetration_report():

    result = get_security_report()

    return jsonify(result)

@app.route("/threat_intel")
@login_required
def threat_intel():

    threats = [

        {
            "time": "19:05",
            "name": "Ransomware Campaign",
            "severity": "Critical",
            "status": "Active"
        },

        {
            "time": "18:50",
            "name": "Phishing Domain",
            "severity": "High",
            "status": "Blocked"
        },

        {
            "time": "18:35",
            "name": "Malware Hash",
            "severity": "Medium",
            "status": "Detected"
        },

        {
            "time": "18:20",
            "name": "Botnet IP",
            "severity": "Critical",
            "status": "Active"
        },

        {
            "time": "18:05",
            "name": "SQL Injection Attempt",
            "severity": "High",
            "status": "Blocked"
        }

    ]

    return render_template(
        "threat_intel.html",
        threats=threats
    )
# ======================================
# Upload Page
# ======================================
@app.route("/change_password", methods=["GET","POST"])
@login_required
def change_password():

    if request.method == "POST":

        old = request.form["old_password"]
        new = request.form["new_password"]

        username = current_user.username

        if users[username]["password"] == old:

            users[username]["password"] = new

            flash("Password changed successfully.")

            return redirect(url_for("profile"))

        flash("Current password is incorrect.")

    return render_template("change_password.html")
@app.errorhandler(404)
def page_not_found(e):

    return render_template("404.html"),404


@app.errorhandler(500)
def internal_error(e):

    return render_template("500.html"),500
@app.route("/chatbot", methods=["POST"])
def chatbot():

    data=request.get_json()

    msg=data["message"].lower()

    if "malware" in msg:

        reply="Malware is software designed to damage or steal information."

    elif "safe" in msg:

        reply="Safe files contain no detected malicious behaviour."

    elif "virus" in msg:

        reply="A virus is a malicious program that spreads between files."

    elif "phishing" in msg:

        reply="Phishing attempts to steal passwords through fake websites."

    elif "trojan" in msg:

        reply="A Trojan disguises itself as legitimate software."

    else:

        reply="I'm your AI Security Assistant. Ask me about malware, ransomware, phishing, scans, or cyber security."

    return jsonify({"reply":reply})



@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Handles file uploads with extension verification and redirects to scanning."""
    if request.method == "POST":
        if "file" not in request.files:
            flash("Please choose a file.")
            return redirect(request.url)

        file = request.files["file"]
        if file.filename == "":
            flash("No file selected.")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash("Unsupported file type.")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        return redirect(url_for("scan_file", filename=filename))

    return render_template("upload.html")
@app.route("/scanning/<filename>")
@login_required
def scanning(filename):

    return render_template(
        "scanning.html",
        filename=filename
    )

@app.route("/scan/<filename>")
@login_required
def scan_file(filename):
    """Executes ML threat scanning on saved uploads."""
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    features = extract_features(filepath)
    result = predict(features)
    save_scan(filename, features, result)

    return render_template(
        "result.html",
        filename=filename,
        features=features,
        result=result,
        prediction=result.get("prediction", "Unknown"),
        risk=result.get("risk_level", result.get("risk", "Low")),
        confidence=result.get("confidence", 0.0),
        accuracy="100.00%",
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        recommendation=result.get("recommendation", "")
    )


@app.route("/export/csv")
@login_required
def export_csv():

    scans = get_all_scans()

    output = StringIO()

    writer = csv.writer(output)

    writer.writerow([

        "Filename",

        "Prediction",

        "Risk",

        "Confidence",

        "Scan Time"

    ])

    for scan in scans:

        writer.writerow([

            scan["filename"],

            scan["prediction"],

            scan["risk"],

            scan["confidence"],

            scan["scan_time"]

        ])

    output.seek(0)

    return Response(

        output,

        mimetype="text/csv",

        headers={

            "Content-Disposition":

            "attachment; filename=AI_Threat_Report.csv"

        }

    )
@app.route("/export/pdf")
@login_required
def export_pdf():

    scans = get_all_scans()

    filename = "AI_Threat_Report.pdf"

    pdf = SimpleDocTemplate(filename)

    elements = []

    styles = getSampleStyleSheet()

    title = Paragraph(

        "<b><font size=18>AI Threat Detection Report</font></b>",

        styles["Title"]

    )

    elements.append(title)

    elements.append(Paragraph("<br/>", styles["Normal"]))

    data = [

        [

            "File",

            "Prediction",

            "Risk",

            "Confidence",

            "Scan Time"

        ]

    ]

    for scan in scans:

        data.append([

            scan["filename"],

            scan["prediction"],

            scan["risk"],

            str(scan["confidence"]),

            scan["scan_time"]

        ])

    table = Table(data)

    table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),colors.darkblue),

        ("TEXTCOLOR",(0,0),(-1,0),colors.white),

        ("GRID",(0,0),(-1,-1),1,colors.grey),

        ("BACKGROUND",(0,1),(-1,-1),colors.beige),

        ("ALIGN",(0,0),(-1,-1),"CENTER"),

        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),

        ("BOTTOMPADDING",(0,0),(-1,0),12)

    ]))

    elements.append(table)

    pdf.build(elements)

    return send_file(

        filename,

        as_attachment=True

    )

@app.route("/analytics")
@login_required
def analytics():

    stats = dashboard_stats()

    daily = scans_per_day()

    risk = risk_distribution()

    months = monthly_scans()

    score = security_score()

    # Daily Trend
    if daily:

        df = pd.DataFrame(
            daily,
            columns=["Date","Scans"]
        )

        line = px.line(
            df,
            x="Date",
            y="Scans",
            markers=True,
            title="Daily Threat Trend"
        )

    else:

        line = px.line(
            pd.DataFrame({
                "Date":[],
                "Scans":[]
            }),
            x="Date",
            y="Scans"
        )

    line.update_layout(template="plotly_dark")

    # Risk Distribution
    if risk:

        rdf = pd.DataFrame(
            risk,
            columns=["Risk","Count"]
        )

        bar = px.bar(
            rdf,
            x="Risk",
            y="Count",
            title="Threat Risk Levels"
        )

    else:

        bar = px.bar(
            pd.DataFrame({
                "Risk":[],
                "Count":[]
            }),
            x="Risk",
            y="Count"
        )

    bar.update_layout(template="plotly_dark")

    # Monthly Trend
    if months:

        mdf = pd.DataFrame(
            months,
            columns=["Month","Scans"]
        )

        monthly = px.line(
            mdf,
            x="Month",
            y="Scans",
            markers=True,
            title="Monthly Scan Trend"
        )

    else:

        monthly = px.line(
            pd.DataFrame({
                "Month":[],
                "Scans":[]
            }),
            x="Month",
            y="Scans"
        )

    monthly.update_layout(template="plotly_dark")

    return render_template(

        "analytics.html",

        stats=stats,

        score=score,

        line=line.to_html(full_html=False),

        bar=bar.to_html(full_html=False),

        monthly=monthly.to_html(full_html=False)

    )

@app.route("/settings")
@login_required
def settings():

    return render_template(

        "settings.html",

        user=current_user.id,

        role=current_user.role

    )

@app.route("/profile")
@login_required
def profile():

    return render_template(

        "profile.html",

        user=current_user.id,

        role=current_user.role

    )

@app.route("/api/notifications")
@login_required
def notifications():
    """Returns real-time notifications for recent scan results."""
    recent = recent_scans(1)
    if not recent:
        return {"notification": False}

    scan = recent[0]
    return {
        "notification": True,
        "filename": scan["filename"],
        "prediction": scan["prediction"],
        "risk": scan["risk"],
        "time": scan["scan_time"]
    }

@app.route("/qr-scan")
@login_required
def qr_scan():
    return render_template("qr_scan.html") 


from werkzeug.security import check_password_hash


@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("signup"))

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect("database/threat.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

        try:

            cursor.execute("""
            INSERT INTO users(username,email,password)
            VALUES(?,?,?)
            """, (username, email, hashed_password))

            conn.commit()

            flash("Registration Successful! Please Login.", "success")

        except sqlite3.IntegrityError:

            flash("Email already exists.", "error")

        conn.close()

        return redirect(url_for("login"))

    return render_template("signup.html")
# ======================================
# Run Flask
# =======
from database.db import init_db

if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)

