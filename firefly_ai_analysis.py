#!/usr/bin/env python3
"""
Firefly III AI Transaction Analysis Script
==========================================
Uses Claude (Anthropic API) to perform a holistic, intelligent review of
your recent transactions and flag anything suspicious or worth reviewing.

Unlike the rule-based fraud detection script, this script sends your
transactions to Claude for free-form reasoning — it can catch subtle patterns,
unusual sequences, and anomalies that are hard to encode as fixed rules.

⚠️  Privacy notice: your transaction data (amounts, merchants, dates,
    descriptions) is sent to Anthropic's API. No account numbers or IBANs
    are included. See https://www.anthropic.com/privacy for Anthropic's policy.

Usage:
  pip install requests anthropic --break-system-packages
  python3 firefly_ai_analysis.py

Scheduling (DSM Task Scheduler — e.g. Sunday 08:00):
  python3 /volume1/docker/firefly/firefly_ai_analysis.py
"""

import json
import os
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

# ============================================================
# LOAD CONFIGURATION
# ============================================================
import importlib.util, os as _os
_cfg_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "config.py")
_spec = importlib.util.spec_from_file_location("config", _cfg_path)
_cfg  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cfg)

# ============================================================
# CONFIGURATION — loaded from config.py
# ============================================================

FIREFLY_URL       = _cfg.FIREFLY_URL
FIREFLY_TOKEN     = _cfg.FIREFLY_TOKEN
ANTHROPIC_API_KEY = _cfg.ANTHROPIC_API_KEY
LOOKBACK_DAYS     = _cfg.ANALYSIS_LOOKBACK_DAYS
MAX_TRANSACTIONS  = _cfg.ANALYSIS_MAX_TRANSACTIONS
SMTP_HOST         = _cfg.SMTP_HOST
SMTP_PORT         = _cfg.SMTP_PORT
SMTP_USER         = _cfg.SMTP_USER
SMTP_PASS         = _cfg.SMTP_PASS
SMTP_FROM         = _cfg.SMTP_FROM_ANALYSIS
SMTP_TO           = _cfg.SMTP_TO
MAIL_ENCRYPTION   = _cfg.MAIL_ENCRYPTION
LAST_RUN_FILE     = _cfg.ANALYSIS_LAST_RUN_FILE

# ============================================================
# FIREFLY API
# ============================================================

SESSION = requests.Session()
SESSION.headers.update({
    "Authorization": f"Bearer {FIREFLY_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
})

def get_transactions(start: datetime, end: datetime) -> list:
    """Fetch all transactions in date range, handling pagination."""
    transactions = []
    page = 1
    start_str = start.strftime("%Y-%m-%d")
    end_str   = end.strftime("%Y-%m-%d")

    while True:
        resp = SESSION.get(
            f"{FIREFLY_URL}/api/v1/transactions",
            params={"start": start_str, "end": end_str, "page": page, "limit": 100},
        )
        resp.raise_for_status()
        data = resp.json()
        transactions.extend(data.get("data", []))
        meta = data.get("meta", {}).get("pagination", {})
        if page >= meta.get("total_pages", 1):
            break
        page += 1

    return transactions

def parse_transactions(raw: list) -> list:
    """Flatten and clean Firefly's nested transaction structure."""
    result = []
    for tx in raw:
        attrs = tx.get("attributes", {})
        for split in attrs.get("transactions", []):
            result.append({
                "id":          tx.get("id"),
                "date":        split.get("date", "")[:10],
                "amount":      float(split.get("amount", 0)),
                "currency":    split.get("currency_code", "EUR"),
                "description": split.get("description", ""),
                "merchant":    (split.get("destination_name") or split.get("source_name") or "").strip(),
                "type":        split.get("type", ""),
                "source":      split.get("source_name", ""),
                "destination": split.get("destination_name", ""),
                "foreign_currency": split.get("foreign_currency_code"),
                "foreign_amount":   split.get("foreign_amount"),
                "category":    split.get("category_name", ""),
                "notes":       (split.get("notes") or "").strip(),
            })
    return result

def format_for_claude(transactions: list) -> str:
    """Format transactions as a compact JSON-like list for Claude."""
    lines = []
    for tx in transactions:
        merchant = tx["merchant"] or tx["description"] or "(inconnu)"
        foreign = f" [{tx['foreign_currency']} {tx['foreign_amount']}]" if tx.get("foreign_currency") else ""
        category = f" | cat: {tx['category']}" if tx.get("category") else ""
        notes = f" | notes: {tx['notes']}" if tx.get("notes") else ""
        lines.append(
            f"[{tx['date']}] ID:{tx['id']} {tx['type']:10} "
            f"{tx['amount']:10.2f} {tx['currency']} "
            f"| {tx['source']} → {tx['destination']}"
            f"{foreign}{category}{notes}"
            f" | description: {tx['description']}"
        )
    return "\n".join(lines)

# ============================================================
# CLAUDE AI ANALYSIS
# ============================================================

CLAUDE_MODEL = "claude-sonnet-4-20250514"

SYSTEM_PROMPT = """Tu es un expert en analyse de transactions bancaires personnelles et en détection de fraude.
Tu analyses les transactions d'un particulier français et tu identifies tout ce qui mérite attention.

Ton rôle est d'identifier :
- Les transactions suspectes ou potentiellement frauduleuses
- Les montants inhabituels (très élevés ou incohérents avec le profil)
- Les transactions nocturnes (entre minuit et 6h du matin)
- Les doublons possibles (même montant, même marchand, à quelques heures d'intervalle)
- Les transactions en devise étrangère inhabituelles
- Les marchands inconnus ou avec des noms suspects
- Les dépenses récurrentes qui ont changé de montant
- Les séquences de petites transactions qui ensemble représentent un montant significatif
- Tout autre pattern qui mérite l'attention du propriétaire du compte

Pour chaque anomalie détectée, tu indiques :
1. L'ID de la transaction concernée
2. Une description claire du problème en français
3. Le niveau de risque : 🔴 ÉLEVÉ, 🟡 MOYEN, 🟢 À VÉRIFIER

Si tout semble normal, dis-le clairement.
Réponds uniquement en français.
Sois concis mais précis. Ne répète pas les données brutes — interprète-les."""

def analyze_with_claude(transactions_text: str, period_start: str, period_end: str) -> str:
    """Send transactions to Claude API for analysis."""
    user_message = f"""Voici les transactions bancaires de la période du {period_start} au {period_end}.
Analyse-les et signale tout ce qui mérite attention.

TRANSACTIONS :
{transactions_text}

Commence par un résumé général (2-3 phrases), puis liste les anomalies détectées.
Si rien de suspect, indique-le brièvement."""

    payload = {
        "model": CLAUDE_MODEL,
        "max_tokens": 2048,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": user_message}
        ]
    }

    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=payload,
        timeout=120,
    )
    if not resp.ok:
        print(f"  → Erreur API Claude {resp.status_code}: {resp.text}")
    resp.raise_for_status()
    data = resp.json()

    # Extract text from response
    content = data.get("content", [])
    text_blocks = [block["text"] for block in content if block.get("type") == "text"]
    return "\n".join(text_blocks)

# ============================================================
# EMAIL
# ============================================================

def build_email_body(analysis: str, period_start: str, period_end: str,
                     tx_count: int, generated_at: str) -> str:
    lines = [
        "Analyse IA des transactions Firefly III",
        f"Période : {period_start} → {period_end}",
        f"Généré le : {generated_at}",
        f"Transactions analysées : {tx_count}",
        "=" * 60,
        "",
        analysis,
        "",
        "=" * 60,
        f"Ce rapport a été généré automatiquement par Claude ({CLAUDE_MODEL}).",
        f"Vérifiez vos transactions sur : {FIREFLY_URL}",
        "",
        "⚠️  Note : vos données de transaction (montants, marchands, dates) ont été",
        "    envoyées à l'API Anthropic pour cette analyse.",
    ]
    return "\n".join(lines)

def send_email(subject: str, body: str):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM
    msg["To"]      = SMTP_TO
    msg.attach(MIMEText(body, "plain", "utf-8"))

    if MAIL_ENCRYPTION == "ssl":
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if MAIL_ENCRYPTION == "tls":
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())

# ============================================================
# LAST RUN TRACKING
# ============================================================

def load_last_run() -> dict:
    if os.path.exists(LAST_RUN_FILE):
        try:
            with open(LAST_RUN_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}

def save_last_run(period_start: str, period_end: str, tx_count: int):
    data = {
        "last_run": datetime.now(timezone.utc).isoformat(),
        "period_start": period_start,
        "period_end": period_end,
        "tx_count": tx_count,
    }
    with open(LAST_RUN_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ============================================================
# MAIN
# ============================================================

def main():
    now   = datetime.now(timezone.utc)
    start = now - timedelta(days=LOOKBACK_DAYS)

    period_start = start.strftime("%Y-%m-%d")
    period_end   = now.strftime("%Y-%m-%d")
    generated_at = now.strftime("%Y-%m-%d %H:%M UTC")

    print(f"[{generated_at}] Récupération des transactions...")
    raw = get_transactions(start, now)
    transactions = parse_transactions(raw)
    print(f"  → {len(transactions)} transactions récupérées")

    if not transactions:
        print("Aucune transaction dans la période — aucun email envoyé.")
        return

    # Limit to MAX_TRANSACTIONS most recent
    if len(transactions) > MAX_TRANSACTIONS:
        print(f"  → Troncature à {MAX_TRANSACTIONS} transactions (les plus récentes)")
        transactions = sorted(transactions, key=lambda x: x["date"], reverse=True)[:MAX_TRANSACTIONS]

    print("Envoi à Claude pour analyse...")
    transactions_text = format_for_claude(transactions)
    analysis = analyze_with_claude(transactions_text, period_start, period_end)
    print("  → Analyse reçue")

    print("\n" + "=" * 60)
    print(analysis)
    print("=" * 60 + "\n")

    body    = build_email_body(analysis, period_start, period_end, len(transactions), generated_at)
    subject = f"🤖 Firefly III — Analyse IA du {period_start} au {period_end}"

    print("Envoi de l'email...")
    send_email(subject, body)

    save_last_run(period_start, period_end, len(transactions))
    print("Terminé.")

if __name__ == "__main__":
    main()
