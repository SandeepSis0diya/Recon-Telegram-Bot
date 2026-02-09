import asyncio
import subprocess
import re
import datetime
import os
import ipaddress

from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from telegram.request import HTTPXRequest

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

# ================= CONFIG =================
BOT_TOKEN = "your_telegram_bot_token_here"
NETWORK_RANGE = "192.168.29.0/24"

NUCLEI_PATH = "/usr/bin/nuclei"
WHATWEB_PATH = "/usr/bin/whatweb"
NIKTO_PATH = "/usr/bin/nikto"
DIRSEARCH_PATH = "/usr/bin/dirsearch"

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# ================= TELEGRAM =================
request = HTTPXRequest(connect_timeout=30, read_timeout=30, write_timeout=30)

# ================= FULL SEVERITY RULES =================
SEVERITY_RULES = {
    "High": {
        "Outdated / End-of-Life Software": [
            "outdated", "end of life", "eol", "unsupported",
            "apache/2.2", "php/5.", "openssl 1.0"
        ],
        "FTP Service Exposed": ["ftp", "anonymous ftp"],
        "Remote Code Execution Indicators": ["rce", "cve-", "command execution"],
        "Authentication Bypass Indicators": ["auth bypass", "default credentials"],
        "Critical Admin Interfaces Exposed": [
            "phpmyadmin", "adminer", "jenkins", "grafana"
        ]
    },
    "Medium": {
        "Directory Listing Enabled": ["index of /", "directory indexing"],
        "Sensitive Backup Files Exposed": [".bak", ".backup", ".old", ".env", ".sql"],
        "Server Status Page Accessible": ["server-status"],
        "Dangerous HTTP Methods Enabled": ["options method", "put", "delete"],
        "Information Disclosure": ["stack trace", "internal ip", "debug"]
    },
    "Low": {
        "Missing HTTP Security Headers": [
            "missing-security-headers",
            "x-frame-options",
            "content-security-policy",
            "strict-transport-security"
        ],
        "Cookie Security Flags Missing": ["httponly", "secure flag not set"],
        "Technology Fingerprinting": ["x-powered-by", "powered by"]
    }
}

# ================= UTILS =================
def clean_output(text):
    return re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)

async def run_cmd(cmd, timeout=None):
    result = await asyncio.to_thread(
        subprocess.run, cmd, capture_output=True, text=True, timeout=timeout
    )
    return clean_output(result.stdout + result.stderr)

async def send_output(update, title, output):
    await update.message.reply_text(f"📌 {title}")
    if not output.strip():
        await update.message.reply_text("(no findings)")
        return
    for i in range(0, len(output), 3800):
        await update.message.reply_text(output[i:i + 3800])

# ================= SEVERITY DETECTION =================
def detect_severity(results):
    combined = " ".join(results.values()).lower()
    findings = {"High": [], "Medium": [], "Low": []}

    for severity, risks in SEVERITY_RULES.items():
        for risk, keywords in risks.items():
            if any(k in combined for k in keywords):
                findings[severity].append(risk)

    return findings

# ================= TOOL RUNNERS =================
async def run_nmap(target):
    return await run_cmd(["nmap", "-T4", "-p-", "-A", target])

async def run_web(target):
    return await run_cmd([WHATWEB_PATH, f"http://{target}"])

async def run_nuc(target):
    return await run_cmd([NUCLEI_PATH, "-u", f"http://{target}", "-silent"])

async def run_nik(target):
    return await run_cmd([NIKTO_PATH, "-h", f"http://{target}"], timeout=240)

# -------- FIXED DIRSEARCH --------
async def run_dir(target):
    report_file = os.path.join(
        REPORT_DIR, f"dirsearch_{target.replace(':','_')}.txt"
    )

    cmd = [
        DIRSEARCH_PATH,
        "-u", f"http://{target}/",
        "--format", "plain",
        "--output", report_file,
        "--quiet",
        "--no-color",
        "--exclude-status", "404"
    ]

    await run_cmd(cmd, timeout=300)

    if os.path.exists(report_file):
        with open(report_file, "r", errors="ignore") as f:
            lines = f.readlines()

        findings = [
            line.strip() for line in lines
            if line.strip()
            and not line.startswith("[")
            and "Starting:" not in line
        ]

        return "\n".join(findings) if findings else "No directories found."

    return "Dirsearch produced no output."

# ================= PDF =================
def generate_pdf(target, results):
    filename = f"recon_report_{target.replace(':','_')}.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(filename, pagesize=A4)
    story = []

    severity = detect_severity(results)

    story.append(Paragraph("Executive Summary", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Target:</b> {target}", styles["Normal"]))
    story.append(Paragraph(
        f"<b>Date:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]
    ))

    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>High Severity Findings:</b> {len(severity['High'])}", styles["Normal"]))
    story.append(Paragraph(f"<b>Medium Severity Findings:</b> {len(severity['Medium'])}", styles["Normal"]))
    story.append(Paragraph(f"<b>Low Severity Findings:</b> {len(severity['Low'])}", styles["Normal"]))

    story.append(Spacer(1, 20))
    story.append(Paragraph("Key Risks Identified", styles["Heading2"]))

    for sev in ["High", "Medium", "Low"]:
        if severity[sev]:
            story.append(Paragraph(f"<b>{sev}:</b>", styles["Normal"]))
            for r in severity[sev]:
                story.append(Paragraph(f"- {r}", styles["Normal"]))

    story.append(PageBreak())

    for section, output in results.items():
        story.append(Paragraph(section, styles["Heading2"]))
        for line in output.splitlines():
            story.append(Paragraph(line.replace("<", "&lt;"), styles["Code"]))
        story.append(PageBreak())

    doc.build(story)
    return filename

# ================= COMMANDS =================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 Recon Bot (IPv4 only)\n\n"
        "Manual mode:\n"
        "/net\n"
        "/nmap <IP>\n"
        "/web <IP>\n"
        "/nuc <IP>\n"
        "/nik <IP>\n"
        "/dir <IP>\n\n"
        "Auto mode:\n"
        "/recon <IP[:PORT]>"
    )

async def net(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🌐 Running network discovery…")
    out = await run_cmd(["nmap", "-sn", NETWORK_RANGE])
    await send_output(update, "Network scan", out)

# -------- Manual mode --------
async def manual(update, context, runner, name):
    if len(context.args) != 1:
        await update.message.reply_text(f"Usage: /{name} <IP>")
        return
    await update.message.reply_text(f"▶️ Running {name}…")
    out = await runner(context.args[0])
    await send_output(update, name.upper(), out)

async def nmap_cmd(u, c): await manual(u, c, run_nmap, "nmap")
async def web_cmd(u, c): await manual(u, c, run_web, "web")
async def nuc_cmd(u, c): await manual(u, c, run_nuc, "nuc")
async def nik_cmd(u, c): await manual(u, c, run_nik, "nik")
async def dir_cmd(u, c): await manual(u, c, run_dir, "dir")

# -------- Auto mode --------
async def recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /recon <IP[:PORT]>")
        return

    target = context.args[0]
    results = {}

    await update.message.reply_text("🔍 Starting auto recon…")

    for name, runner in [
        ("Nmap Scan", run_nmap),
        ("WhatWeb Scan", run_web),
        ("Nuclei Scan", run_nuc),
        ("Nikto Scan", run_nik),
        ("Dirsearch Scan", run_dir),
    ]:
        await update.message.reply_text(f"▶️ Running {name}…")
        out = await runner(target)
        results[name] = out
        await send_output(update, name, out)

    await update.message.reply_text("📄 Generating PDF report…")
    pdf = generate_pdf(target, results)
    await update.message.reply_document(open(pdf, "rb"), filename=pdf)

    await update.message.reply_text("✅ Auto recon completed")

# ================= APP =================
app = ApplicationBuilder().token(BOT_TOKEN).request(request).build()

app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("net", net))
app.add_handler(CommandHandler("nmap", nmap_cmd))
app.add_handler(CommandHandler("web", web_cmd))
app.add_handler(CommandHandler("nuc", nuc_cmd))
app.add_handler(CommandHandler("nik", nik_cmd))
app.add_handler(CommandHandler("dir", dir_cmd))
app.add_handler(CommandHandler("recon", recon))

print("[+] Recon Bot running (DIRSEARCH FIXED)")
app.run_polling(drop_pending_updates=True)
