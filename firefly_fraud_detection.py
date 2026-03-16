#!/usr/bin/env python3
"""
Firefly III Fraud Detection Script
====================================
Detects suspicious transactions and sends an email report.

Patterns detected:
  - Unusual amounts (> 3 standard deviations from mean per account)
  - Transactions at unusual times (between 00:00 and 06:00)
  - Unknown / new merchants (first seen in last N days)
  - Duplicate transactions (same amount + merchant within 24h)
  - Foreign country transactions (non-EU IBAN or flagged currency)

Usage:
  python3 firefly_fraud_detection.py

Scheduling (add to crontab):
  0 7 * * * python3 /path/to/firefly_fraud_detection.py
"""

import json
import os
import smtplib
import statistics
from collections import defaultdict
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

FIREFLY_URL             = _cfg.FIREFLY_URL
FIREFLY_TOKEN           = _cfg.FIREFLY_TOKEN
LOOKBACK_DAYS           = _cfg.FRAUD_LOOKBACK_DAYS
AMOUNT_STDDEV_THRESHOLD = _cfg.AMOUNT_STDDEV_THRESHOLD
NIGHT_HOUR_START        = _cfg.NIGHT_HOUR_START
NIGHT_HOUR_END          = _cfg.NIGHT_HOUR_END
HOME_CURRENCIES         = _cfg.HOME_CURRENCIES
HOME_IBAN_PREFIXES      = _cfg.HOME_IBAN_PREFIXES
SMTP_HOST               = _cfg.SMTP_HOST
SMTP_PORT               = _cfg.SMTP_PORT
SMTP_USER               = _cfg.SMTP_USER
SMTP_PASS               = _cfg.SMTP_PASS
SMTP_FROM               = _cfg.SMTP_FROM_FRAUD
SMTP_TO                 = _cfg.SMTP_TO
MAIL_ENCRYPTION         = _cfg.MAIL_ENCRYPTION
ALERTED_IDS_FILE        = _cfg.ALERTED_IDS_FILE
AI_MERCHANT_TAG         = _cfg.AI_MERCHANT_TAG
VERIFIED_TAG            = _cfg.VERIFIED_TAG
MERCHANT_WHITELIST_FILE = _cfg.MERCHANT_WHITELIST_FILE

# ============================================================
# FIREFLY API HELPERS
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

# Merchant name values that are considered empty/missing
# Defined here so get_all_merchants can reference it when building the known set
EMPTY_MERCHANT_PLACEHOLDERS = {"(no name)", "(unknown)", "(none)", ""}

def get_all_merchants(before: datetime) -> set:
    """Fetch all merchant names ever seen before the current analysis window.
    Any merchant appearing before LOOKBACK_DAYS ago is considered 'known'.
    Merchants only appearing within LOOKBACK_DAYS are flagged as new."""
    merchants = set()
    page = 1
    far_start = before - timedelta(days=365 * 10)  # look back up to 10 years
    start_str = far_start.strftime("%Y-%m-%d")
    end_str   = (before - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%d")

    while True:
        resp = SESSION.get(
            f"{FIREFLY_URL}/api/v1/transactions",
            params={"start": start_str, "end": end_str, "page": page, "limit": 100},
        )
        resp.raise_for_status()
        data = resp.json()
        for tx in data.get("data", []):
            for split in tx.get("attributes", {}).get("transactions", []):
                name = (split.get("destination_name") or split.get("source_name") or "").strip()
                if name and name.lower() not in EMPTY_MERCHANT_PLACEHOLDERS:
                    merchants.add(name.strip().lower())
        meta = data.get("meta", {}).get("pagination", {})
        if page >= meta.get("total_pages", 1):
            break
        page += 1

    return merchants

# ============================================================
# DETECTION FUNCTIONS
# ============================================================

def parse_transactions(raw: list) -> list:
    """Flatten Firefly's nested transaction structure."""
    result = []
    for tx in raw:
        attrs = tx.get("attributes", {})
        for split in attrs.get("transactions", []):
            result.append({
                "id":          tx.get("id"),
                "date":        split.get("date", ""),
                "amount":      float(split.get("amount", 0)),
                "currency":    split.get("currency_code", ""),
                "description": split.get("description", ""),
                "merchant":    (split.get("destination_name") or split.get("source_name") or "").strip(),
                "type":        split.get("type", ""),
                "source":      split.get("source_name", ""),
                "destination": split.get("destination_name", ""),
                "foreign_currency": split.get("foreign_currency_code"),
                "notes":       split.get("notes", "") or "",
                "tags":        split.get("tags") or [],
            })
    return result

def detect_unusual_amounts(transactions: list) -> list:
    """Flag amounts > N std deviations from the mean per source account."""
    by_account = defaultdict(list)
    for tx in transactions:
        if tx["type"] == "withdrawal":
            by_account[tx["source"]].append(tx)

    flagged = []
    for account, txs in by_account.items():
        if len(txs) < 5:
            continue  # not enough data for statistics
        amounts = [t["amount"] for t in txs]
        mean   = statistics.mean(amounts)
        stdev  = statistics.stdev(amounts)
        if stdev == 0:
            continue
        for tx in txs:
            z_score = (tx["amount"] - mean) / stdev
            if z_score > AMOUNT_STDDEV_THRESHOLD:
                flagged.append({
                    **tx,
                    "reason": f"Montant inhabituel (€{tx['amount']:.2f} — {z_score:.1f}x l'écart-type au-dessus de la moyenne de €{mean:.2f})"
                })
    return flagged

def detect_night_transactions(transactions: list) -> list:
    """Flag transactions made during night hours."""
    flagged = []
    for tx in transactions:
        if tx["type"] not in ("withdrawal", "deposit"):
            continue
        try:
            dt = datetime.fromisoformat(tx["date"].replace("Z", "+00:00"))
            # Convert to local time (Paris = UTC+1/UTC+2)
            local_hour = (dt.hour + 1) % 24  # rough CET offset
            if NIGHT_HOUR_START <= local_hour <= NIGHT_HOUR_END:
                flagged.append({
                    **tx,
                    "reason": f"Transaction à une heure inhabituelle ({local_hour:02d}:00 heure locale)"
                })
        except (ValueError, AttributeError):
            continue
    return flagged

def detect_missing_merchants(transactions: list, whitelist: list) -> list:
    """Flag withdrawals where the merchant name is empty or a placeholder.
    Since merchants are populated by Firefly rules and the AI categorize script,
    a missing name after both have run means something genuinely slipped through.
    Skips transactions whose description matches a whitelisted keyword (for
    legitimate no-merchant transactions like transfers or salary credits)."""
    flagged = []
    for tx in transactions:
        if tx["type"] != "withdrawal":
            continue
        merchant = tx["merchant"].lower().strip()
        if merchant not in EMPTY_MERCHANT_PLACEHOLDERS:
            continue
        description = tx["description"].lower()
        if any(keyword in description for keyword in whitelist):
            continue  # legitimate no-merchant transaction
        flagged.append({
            **tx,
            "reason": f"Nom du marchand manquant — aucune règle ne correspond à cette transaction (description : '{tx['description']}')"
        })
    return flagged

def detect_new_merchants(transactions: list, known_merchants: set, whitelist: list) -> list:
    """Flag withdrawals with a merchant name never seen before the current analysis window.
    Skips transactions already carrying VERIFIED_TAG or AI_MERCHANT_TAG.
    Skips merchants whose name matches a whitelist entry."""
    flagged = []
    for tx in transactions:
        if tx["type"] != "withdrawal":
            continue
        tags = tx.get("tags", [])
        if VERIFIED_TAG in tags:
            continue
        if AI_MERCHANT_TAG in tags:
            continue
        merchant = tx["merchant"].lower().strip()
        if not merchant or merchant in EMPTY_MERCHANT_PLACEHOLDERS:
            continue
        if merchant in known_merchants:
            continue
        if any(keyword in merchant for keyword in whitelist):
            continue
        flagged.append({
            **tx,
            "reason": f"Nouveau marchand inconnu : '{tx['merchant']}' — jamais vu avant les {LOOKBACK_DAYS} derniers jours"
        })
    return flagged

def detect_ai_merchants(transactions: list) -> list:
    """Flag withdrawals whose merchant was assigned by the AI categorize script
    (identified by the AI_MERCHANT_TAG tag) and hasn't been validated yet.
    Skipped if the VERIFIED_TAG is also present — meaning you've reviewed and
    approved the transaction by adding that tag manually in Firefly."""
    flagged = []
    for tx in transactions:
        if tx["type"] != "withdrawal":
            continue
        tags = tx.get("tags", [])
        if AI_MERCHANT_TAG in tags and VERIFIED_TAG not in tags:
            flagged.append({
                **tx,
                "reason": f"Marchand '{tx['merchant']}' assigné par l'IA — à valider (ajouter le tag '{VERIFIED_TAG}' une fois vérifié)"
            })
    return flagged

def detect_duplicates(transactions: list) -> list:
    """Flag transactions with same amount + merchant within 24 hours."""
    flagged = []
    seen = []
    withdrawals = [t for t in transactions if t["type"] == "withdrawal"]
    withdrawals.sort(key=lambda x: x["date"])

    for i, tx in enumerate(withdrawals):
        try:
            dt_i = datetime.fromisoformat(tx["date"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        for j in range(i + 1, len(withdrawals)):
            tx2 = withdrawals[j]
            try:
                dt_j = datetime.fromisoformat(tx2["date"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                continue
            if (dt_j - dt_i).total_seconds() > 86400:
                break
            if (
                abs(tx["amount"] - tx2["amount"]) < 0.01
                and tx["merchant"].lower() == tx2["merchant"].lower()
                and tx["id"] not in [f["id"] for f in flagged]
            ):
                dt_i_str = dt_i.strftime("%Y-%m-%d %H:%M")
                dt_j_str = dt_j.strftime("%Y-%m-%d %H:%M")
                flagged.append({
                    **tx,
                    "reason": (
                        f"Doublon possible : même montant €{tx['amount']:.2f} chez '{tx['merchant']}' dans les 24h\n"
                        f"    TX1: [{dt_i_str}] {tx['description']}\n"
                        f"    🔗 {FIREFLY_URL}/transactions/show/{tx['id']}\n"
                        f"    TX2: [{dt_j_str}] {tx2['description']}\n"
                        f"    🔗 {FIREFLY_URL}/transactions/show/{tx2['id']}"
                    )
                })
    return flagged

def detect_foreign_transactions(transactions: list) -> list:
    """Flag transactions in foreign currencies or with non-home IBANs."""
    flagged = []
    for tx in transactions:
        if tx["type"] not in ("withdrawal", "deposit"):
            continue
        # Foreign currency
        if tx["currency"] not in HOME_CURRENCIES:
            flagged.append({
                **tx,
                "reason": f"Transaction en devise étrangère : {tx['currency']} (€{tx['amount']:.2f})"
            })
            continue
        # Foreign currency conversion
        if tx["foreign_currency"] and tx["foreign_currency"] not in HOME_CURRENCIES:
            flagged.append({
                **tx,
                "reason": f"Conversion en devise étrangère : {tx['foreign_currency']}"
            })
    return flagged

# ============================================================
# EMAIL REPORT
# ============================================================

def format_tx(tx: dict) -> str:
    date = tx["date"][:10] if tx["date"] else "?"
    # Duplicates already embed both links in the reason — skip the generic link
    show_link = "transactions/show" not in tx.get("reason", "")
    link_line = f"    🔗 {FIREFLY_URL}/transactions/show/{tx['id']}\n" if show_link else ""
    return (
        f"  • [{date}] {tx['merchant'] or tx['description']} — "
        f"€{tx['amount']:.2f} ({tx['source']} → {tx['destination']})\n"
        f"    ⚠ {tx['reason']}\n"
        f"{link_line}"
    )

def build_report(results: dict, all_results: dict, period_start: datetime, period_end: datetime) -> str:
    total_new     = sum(len(v) for v in results.values())
    total_skipped = sum(
        len(all_results.get(k, [])) - len(results.get(k, []))
        for k in all_results
        # new_merchants and ai_merchants are never filtered — no skipped count for them
        if k not in ("new_merchants", "ai_merchants")
    )

    lines = [
        "Rapport de détection de fraude Firefly III",
        f"Période : {period_start.strftime('%Y-%m-%d')} → {period_end.strftime('%Y-%m-%d')}",
        f"Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "=" * 60,
        f"Nouvelles alertes : {total_new}   |   Déjà signalées (ignorées) : {total_skipped}",
        "",
    ]

    labels = {
        "unusual_amounts":    "💰 Montants inhabituels",
        "night_transactions": "🌙 Transactions nocturnes",
        "missing_merchants":  "🏷️  Marchand manquant",
        "new_merchants":      "🆕 Nouveau marchand inconnu",
        "ai_merchants":       "🤖 Marchand assigné par l'IA (non validé)",
        "duplicates":         "🔁 Doublons possibles",
        "foreign":            "🌍 Transactions en devise étrangère",
    }

    # Only render sections that have alerts
    has_alerts = False
    for key, label in labels.items():
        items = results.get(key, [])
        if not items:
            continue
        has_alerts = True
        lines.append(f"{label}  ({len(items)})")
        lines.append("-" * 40)
        for tx in items:
            lines.append(format_tx(tx))
        lines.append("")

    if not has_alerts:
        lines.append("✅ Aucune nouvelle alerte.")
        lines.append("")

    # Whitelist suggestions
    new_merchants = results.get("new_merchants", [])
    if new_merchants:
        unique_merchants = sorted(set(tx["merchant"].lower() for tx in new_merchants if tx["merchant"]))
        lines.append("=" * 60)
        lines.append("💡 MARCHANDS À AJOUTER À LA LISTE BLANCHE")
        lines.append(f"   {MERCHANT_WHITELIST_FILE}")
        lines.append("")
        for merchant in unique_merchants:
            lines.append(merchant)
        lines.append("")

    # Skipped transactions (already alerted in a previous run) — collapsed summary
    skipped_lines = []
    for key, label in labels.items():
        if key in ("new_merchants", "ai_merchants"):
            continue  # these are never filtered
        all_items = all_results.get(key, [])
        new_items = results.get(key, [])
        new_ids   = {tx["id"] for tx in new_items}
        skipped   = [tx for tx in all_items if tx["id"] not in new_ids]
        if skipped:
            skipped_lines.append(f"{label}  ({len(skipped)} ignorée(s))")
            skipped_lines.append("-" * 40)
            for tx in skipped:
                skipped_lines.append(format_tx(tx))
            skipped_lines.append("")

    if skipped_lines:
        lines.append("=" * 60)
        lines.append("📋 TRANSACTIONS DÉJÀ SIGNALÉES (pour référence)")
        lines.append("Ces alertes ont déjà été envoyées lors d'une exécution précédente.")
        lines.append("")
        lines.extend(skipped_lines)

    lines.append("=" * 60)
    lines.append("Rapport généré automatiquement — Firefly III")
    lines.append(f"{FIREFLY_URL}")
    return "\n".join(lines)

def send_email(subject: str, body: str):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM
    msg["To"]      = SMTP_TO
    msg.attach(MIMEText(body, "plain"))

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
# ALERT STATE — track already-alerted transaction IDs
# ============================================================


def load_merchant_whitelist() -> list:
    """Load description keywords to suppress in missing-merchant detection.
    Each non-comment line is matched case-insensitively as a substring of
    the transaction description. Auto-creates the file with examples on first run."""
    if not os.path.exists(MERCHANT_WHITELIST_FILE):
        with open(MERCHANT_WHITELIST_FILE, "w") as f:
            f.write("# Mots-clés de description à ignorer dans la détection de marchand manquant\n")
            f.write("# Une entrée par ligne, insensible à la casse, correspondance partielle\n")
            f.write("# Ajoutez ici les transactions légitimes sans marchand (virements, salaire...)\n")
            f.write("#\n")
            f.write("# virement\n")
            f.write("# salaire\n")
            f.write("# remboursement\n")
            f.write("# prelevement sepa\n")
        return []
    entries = []
    with open(MERCHANT_WHITELIST_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line.lower())
    return entries

def update_whitelist_from_verified(transactions: list, whitelist: list) -> int:
    """Scan transactions carrying VERIFIED_TAG that also have a merchant name.
    Any merchant not already in the whitelist is appended to the file automatically.
    Returns the number of newly added entries."""
    to_add = []
    for tx in transactions:
        tags = tx.get("tags", [])
        if VERIFIED_TAG not in tags:
            continue
        merchant = tx["merchant"].strip()
        if not merchant or merchant.lower() in EMPTY_MERCHANT_PLACEHOLDERS:
            continue
        if merchant.lower() not in whitelist and merchant.lower() not in [e.lower() for e in to_add]:
            to_add.append(merchant)

    if not to_add:
        return 0

    with open(MERCHANT_WHITELIST_FILE, "a") as f:
        f.write("\n# Ajouté automatiquement depuis les transactions vérifiées\n")
        for merchant in sorted(to_add, key=str.lower):
            f.write(f"{merchant.lower()}\n")
            whitelist.append(merchant.lower())  # update in-memory list for this run

    return len(to_add)


def load_alerted_ids() -> dict:
    """Load previously alerted transaction IDs from disk."""
    if os.path.exists(ALERTED_IDS_FILE):
        try:
            with open(ALERTED_IDS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}

def save_alerted_ids(alerted: dict):
    """Save alerted transaction IDs to disk."""
    # Prune entries older than 90 days to keep file small
    cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    pruned = {tx_id: data for tx_id, data in alerted.items() if data.get("alerted_at", "") > cutoff}
    with open(ALERTED_IDS_FILE, "w") as f:
        json.dump(pruned, f, indent=2)

def filter_new_alerts(results: dict, alerted: dict) -> dict:
    """Remove transactions that have already been alerted.
    new_merchants and ai_merchants are always included regardless — they should
    appear in every report until explicitly acknowledged via VERIFIED_TAG."""
    no_filter = {"new_merchants", "ai_merchants"}
    filtered = {}
    for key, items in results.items():
        if key in no_filter:
            filtered[key] = items
        else:
            filtered[key] = [tx for tx in items if tx["id"] not in alerted]
    return filtered

def mark_as_alerted(results: dict, alerted: dict):
    """Add newly alerted transaction IDs to the state."""
    now = datetime.now(timezone.utc).isoformat()
    for items in results.values():
        for tx in items:
            alerted[tx["id"]] = {"alerted_at": now, "reason": tx.get("reason", "")}

# ============================================================
# MAIN
# ============================================================

def run() -> dict:
    """Run fraud detection and return structured results.
    Called by firefly_morning_report.py — does not send any email."""
    now   = datetime.now(timezone.utc)
    start = now - timedelta(days=LOOKBACK_DAYS)

    print(f"[{now.strftime('%Y-%m-%d %H:%M')}] Récupération des transactions...")
    raw_transactions = get_transactions(start, now)
    transactions     = parse_transactions(raw_transactions)
    print(f"  → {len(transactions)} transactions récupérées")

    print("Récupération des marchands connus...")
    known_merchants = get_all_merchants(now)
    print(f"  → {len(known_merchants)} marchands connus (hors des {LOOKBACK_DAYS} derniers jours)")

    whitelist = load_merchant_whitelist()
    print(f"  → {len(whitelist)} entrée(s) dans la liste blanche")

    added = update_whitelist_from_verified(transactions, whitelist)
    if added:
        print(f"  → {added} marchand(s) vérifié(s) ajouté(s) automatiquement à la liste blanche")

    print("Analyse en cours...")
    all_results = {
        "unusual_amounts":    detect_unusual_amounts(transactions),
        "night_transactions": detect_night_transactions(transactions),
        "missing_merchants":  detect_missing_merchants(transactions, whitelist),
        "new_merchants":      detect_new_merchants(transactions, known_merchants, whitelist),
        "ai_merchants":       detect_ai_merchants(transactions),
        "duplicates":         detect_duplicates(transactions),
        "foreign":            detect_foreign_transactions(transactions),
    }

    alerted = load_alerted_ids()
    results = filter_new_alerts(all_results, alerted)

    total_new = sum(len(v) for v in results.values())
    print(f"  → {total_new} nouvelle(s) alerte(s)")

    # Save alerted IDs
    mark_as_alerted(results, alerted)
    save_alerted_ids(alerted)

    return {
        "results":     results,
        "all_results": all_results,
        "period_start": start,
        "period_end":   now,
    }


def main():
    """Standalone entry point — runs fraud detection and sends its own email.
    When called from firefly_morning_report.py, use run() directly instead."""
    data       = run()
    results    = data["results"]
    all_results = data["all_results"]
    start      = data["period_start"]
    now        = data["period_end"]

    total_new = sum(len(v) for v in results.values())
    if total_new == 0:
        print("Aucune nouvelle transaction suspecte — aucun email envoyé.")
        return

    report  = build_report(results, all_results, start, now)
    subject = f"⚠️ Firefly III : {total_new} nouvelle(s) alerte(s) de fraude"
    print("\nEnvoi du rapport par email...")
    send_email(subject, report)
    print(f"Terminé. {total_new} alerte(s) envoyée(s).")

if __name__ == "__main__":
    main()
