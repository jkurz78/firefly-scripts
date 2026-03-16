#!/usr/bin/env python3
"""
Firefly III AI Categorization Script
======================================
Runs after the nightly import (e.g. 05:45) and automatically assigns
category, budget, destination account and notes to uncategorized transactions
using Claude (Anthropic API).

What it does:
  1. Fetches transactions from the last LOOKBACK_HOURS (default: 48h)
  2. Filters those missing a category, budget or with a raw destination name
  3. Loads your existing Firefly categories, budgets and expense accounts
  4. Sends the batch to Claude for classification
  5. PATCHes each transaction with Claude's suggestions
  6. Sends an email summary — low-confidence assignments are flagged for review

⚠️  Privacy notice: transaction data (amounts, merchants, descriptions) is sent
    to Anthropic's API. See https://www.anthropic.com/privacy

Usage:
  pip3 install requests --break-system-packages
  python3 firefly_ai_categorize.py

Scheduling (DSM Task Scheduler — e.g. daily at 05:45):
  python3 /volume1/docker/firefly/firefly_ai_categorize.py
"""

import json
import os
import smtplib
import time
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

FIREFLY_URL           = _cfg.FIREFLY_URL
FIREFLY_TOKEN         = _cfg.FIREFLY_TOKEN
ANTHROPIC_API_KEY     = _cfg.ANTHROPIC_API_KEY
LOOKBACK_HOURS        = _cfg.CATEGORIZE_LOOKBACK_HOURS
CONFIDENCE_THRESHOLD  = _cfg.CONFIDENCE_THRESHOLD
ENRICH_NOTES          = _cfg.ENRICH_NOTES
NO_MERCHANT_SKIP_KEYWORDS = _cfg.NO_MERCHANT_SKIP_KEYWORDS
AI_MERCHANT_TAG       = _cfg.AI_MERCHANT_TAG
VERIFIED_TAG          = _cfg.VERIFIED_TAG
SMTP_HOST             = _cfg.SMTP_HOST
SMTP_PORT             = _cfg.SMTP_PORT
SMTP_USER             = _cfg.SMTP_USER
SMTP_PASS             = _cfg.SMTP_PASS
SMTP_FROM             = _cfg.SMTP_FROM_CATEGORIZE
SMTP_TO               = _cfg.SMTP_TO
MAIL_ENCRYPTION       = _cfg.MAIL_ENCRYPTION
LOG_FILE              = _cfg.CATEGORIZE_LOG_FILE

# ============================================================
# FIREFLY API
# ============================================================

SESSION = requests.Session()
SESSION.headers.update({
    "Authorization": f"Bearer {FIREFLY_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
})

def get_recent_transactions(hours: int) -> list:
    """Fetch transactions created in the last N hours."""
    transactions = []
    page = 1
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    start_str = start.strftime("%Y-%m-%d")
    end_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")

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

def get_merchant_history() -> dict:
    """Build a lookup of known merchant names → {category, budget} from all
    past transactions. Only stores entries where the field is actually set —
    transactions with empty category or budget are ignored for that field."""
    history = {}
    page = 1
    far_start = (datetime.now(timezone.utc) - timedelta(days=365 * 10)).strftime("%Y-%m-%d")
    far_end   = (datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)).strftime("%Y-%m-%d")

    while True:
        resp = SESSION.get(
            f"{FIREFLY_URL}/api/v1/transactions",
            params={"start": far_start, "end": far_end, "page": page, "limit": 100},
        )
        resp.raise_for_status()
        data = resp.json()
        for tx in data.get("data", []):
            for split in tx.get("attributes", {}).get("transactions", []):
                merchant = (split.get("destination_name") or "").strip().lower()
                category = (split.get("category_name") or "").strip()
                budget   = (split.get("budget_name") or "").strip()
                if not merchant:
                    continue
                existing = history.get(merchant, {})
                # Only update each field if the source transaction actually has a value —
                # never overwrite a known good value with an empty one
                new_entry = {
                    "category": existing.get("category") or category or "",
                    "budget":   existing.get("budget")   or budget   or "",
                }
                if new_entry["category"] or new_entry["budget"]:
                    history[merchant] = new_entry
        meta = data.get("meta", {}).get("pagination", {})
        if page >= meta.get("total_pages", 1):
            break
        page += 1

    return history


def parse_transactions(raw: list) -> list:
    """Flatten Firefly's nested structure into a flat list."""
    result = []
    for tx in raw:
        attrs = tx.get("attributes", {})
        for split in attrs.get("transactions", []):
            result.append({
                "tx_id":        tx.get("id"),
                "split_index":  0,  # we only handle single-split transactions
                "date":         split.get("date", "")[:10],
                "amount":       float(split.get("amount", 0)),
                "currency":     split.get("currency_code", "EUR"),
                "description":  split.get("description", "").strip(),
                "merchant":     (split.get("destination_name") or "").strip(),
                "type":         split.get("type", ""),
                "source":       split.get("source_name", ""),
                "category":     (split.get("category_name") or "").strip(),
                "budget":       (split.get("budget_name") or "").strip(),
                "notes":        (split.get("notes") or "").strip(),
                "tags":         split.get("tags") or [],
                "foreign_currency": split.get("foreign_currency_code"),
            })
    return result

def needs_categorization(tx: dict) -> bool:
    """Return True if the transaction needs AI processing.
    Processes transactions that are missing category, budget, or merchant name.
    Skips transactions already carrying both AI_MERCHANT_TAG and VERIFIED_TAG.
    Skips transactions with an empty merchant whose description matches
    NO_MERCHANT_SKIP_KEYWORDS (e.g. cash withdrawals — no merchant expected)."""
    if tx["type"] not in ("withdrawal", "deposit"):
        return False
    tags = tx.get("tags", [])
    if AI_MERCHANT_TAG in tags and VERIFIED_TAG in tags:
        return False  # already AI-processed and manually verified

    missing_category = not tx["category"]
    missing_budget   = not tx["budget"] and tx["type"] == "withdrawal"
    missing_merchant = not tx["merchant"] or tx["merchant"].lower() in {"(no name)", "(unknown)", "(none)"}

    if missing_merchant:
        # Skip if description indicates no merchant is expected (e.g. cash withdrawal)
        description = tx["description"].lower()
        if any(kw in description for kw in NO_MERCHANT_SKIP_KEYWORDS):
            return missing_category or missing_budget  # still process if cat/budget missing
        return True  # empty merchant and not a known no-merchant transaction — process it

    return missing_category or missing_budget

def get_categories() -> list:
    """Fetch all categories from Firefly."""
    categories = []
    page = 1
    while True:
        resp = SESSION.get(f"{FIREFLY_URL}/api/v1/categories", params={"page": page})
        resp.raise_for_status()
        data = resp.json()
        for cat in data.get("data", []):
            name = cat.get("attributes", {}).get("name", "")
            if name:
                categories.append(name)
        meta = data.get("meta", {}).get("pagination", {})
        if page >= meta.get("total_pages", 1):
            break
        page += 1
    return sorted(categories)

def get_budgets() -> list:
    """Fetch all active budgets from Firefly."""
    budgets = []
    page = 1
    while True:
        resp = SESSION.get(f"{FIREFLY_URL}/api/v1/budgets", params={"page": page})
        resp.raise_for_status()
        data = resp.json()
        for b in data.get("data", []):
            name = b.get("attributes", {}).get("name", "")
            if name:
                budgets.append(name)
        meta = data.get("meta", {}).get("pagination", {})
        if page >= meta.get("total_pages", 1):
            break
        page += 1
    return sorted(budgets)

def get_expense_accounts() -> list:
    """Fetch all expense accounts (destination payees) from Firefly."""
    accounts = []
    page = 1
    while True:
        resp = SESSION.get(
            f"{FIREFLY_URL}/api/v1/accounts",
            params={"type": "expense", "page": page}
        )
        resp.raise_for_status()
        data = resp.json()
        for acc in data.get("data", []):
            name = acc.get("attributes", {}).get("name", "")
            if name:
                accounts.append(name)
        meta = data.get("meta", {}).get("pagination", {})
        if page >= meta.get("total_pages", 1):
            break
        page += 1
    return sorted(accounts)

def patch_transaction(tx_id: str, updates: dict):
    """
    Update a transaction via the Firefly API.
    updates may contain: category_name, budget_name, destination_name, notes
    """
    resp = SESSION.put(
        f"{FIREFLY_URL}/api/v1/transactions/{tx_id}",
        json={
            "apply_rules": False,   # don't re-trigger rules — we're doing the job here
            "fire_webhooks": False,
            "transactions": [updates],
        }
    )
    resp.raise_for_status()
    return resp.json()

# ============================================================
# CLAUDE AI CLASSIFICATION
# ============================================================

CLAUDE_MODEL = "claude-sonnet-4-20250514"

def build_claude_prompt(transactions: list, categories: list,
                        budgets: list, expense_accounts: list) -> str:
    """Build the user message for Claude."""
    tx_lines = []
    for tx in transactions:
        merchant = tx["merchant"] or tx["description"] or "(inconnu)"
        foreign  = f" [{tx['foreign_currency']}]" if tx.get("foreign_currency") else ""
        tx_lines.append(
            f'  {{"id": "{tx["tx_id"]}", "date": "{tx["date"]}", '
            f'"type": "{tx["type"]}", "amount": {tx["amount"]:.2f}, '
            f'"currency": "{tx["currency"]}{foreign}", '
            f'"description": "{tx["description"]}", '
            f'"merchant_raw": "{tx["merchant"]}", '
            f'"source_account": "{tx["source"]}", '
            f'"current_category": "{tx["category"]}", '
            f'"current_budget": "{tx["budget"]}"'
            f'}}'
        )

    prompt = f"""Voici des transactions bancaires récemment importées qui nécessitent d'être catégorisées.

TRANSACTIONS À TRAITER :
[
{chr(10).join(tx_lines)}
]

CATÉGORIES DISPONIBLES DANS FIREFLY :
{json.dumps(categories, ensure_ascii=False)}

BUDGETS DISPONIBLES DANS FIREFLY :
{json.dumps(budgets, ensure_ascii=False)}

COMPTES DE DÉPENSES (PAYEES) EXISTANTS DANS FIREFLY :
{json.dumps(expense_accounts[:100], ensure_ascii=False)}
(Si le marchand correspond à un compte existant, utilise son nom exact.
 Sinon, propose un nom propre et normalisé — ex: "Amazon", "Carrefour Bio Saint-Germain".)

INSTRUCTIONS :
Pour chaque transaction, détermine :
1. "category_name" — la catégorie la plus appropriée parmi celles disponibles (ou null si aucune ne convient)
2. "budget_name" — le budget approprié parmi ceux disponibles (null pour les dépôts ou si hors budget)
3. "destination_name" — le nom propre du marchand/bénéficiaire (normalise les noms bruts de banque)
4. "notes" — une description courte et lisible en français (ex: "Courses alimentaires", "Abonnement streaming", "Remboursement santé")
5. "confidence" — ta confiance entre 0.0 et 1.0
6. "reason" — brève justification si confidence < {CONFIDENCE_THRESHOLD} (sinon null)

Réponds UNIQUEMENT avec un tableau JSON valide, sans texte avant ni après :
[
  {{
    "id": "...",
    "category_name": "...",
    "budget_name": "...",
    "destination_name": "...",
    "notes": "...",
    "confidence": 0.9,
    "reason": null
  }},
  ...
]"""
    return prompt

SYSTEM_PROMPT = """Tu es un assistant expert en finances personnelles françaises.
Tu catégorises des transactions bancaires avec précision et cohérence.
Tu réponds UNIQUEMENT avec du JSON valide, sans markdown, sans commentaires, sans texte supplémentaire."""

def classify_with_claude(transactions: list, categories: list,
                         budgets: list, expense_accounts: list) -> list:
    """Send transactions to Claude and get back classification JSON."""
    user_message = build_claude_prompt(transactions, categories, budgets, expense_accounts)

    payload = {
        "model": CLAUDE_MODEL,
        "max_tokens": 4096,
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
    resp.raise_for_status()
    data = resp.json()

    content = data.get("content", [])
    text = "\n".join(b["text"] for b in content if b.get("type") == "text")

    # Strip markdown code fences if present
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    text = text.strip()

    return json.loads(text)

# ============================================================
# EMAIL REPORT
# ============================================================

def build_report(applied: list, skipped: list, errors: list,
                 period_start: str, period_end: str) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    low_confidence = [r for r in applied if r.get("confidence", 1.0) < CONFIDENCE_THRESHOLD]
    high_confidence = [r for r in applied if r.get("confidence", 1.0) >= CONFIDENCE_THRESHOLD]

    lines = [
        "Rapport de catégorisation IA — Firefly III",
        f"Période analysée : {period_start} → {period_end}",
        f"Généré le : {now}",
        "=" * 60,
        f"✅ Catégorisées automatiquement : {len(high_confidence)}",
        f"⚠️  Catégorisées (faible confiance) : {len(low_confidence)}",
        f"⏭️  Ignorées (déjà catégorisées) : {len(skipped)}",
        f"❌ Erreurs : {len(errors)}",
        "",
    ]

    if high_confidence:
        lines += [
            "─" * 60,
            f"✅ CATÉGORISÉES AUTOMATIQUEMENT ({len(high_confidence)})",
            "─" * 60,
        ]
        for r in high_confidence:
            lines.append(
                f"  • [{r['date']}] {r['destination_name']} — {r['amount']:.2f} €\n"
                f"    Catégorie : {r['category_name'] or '—'} | Budget : {r['budget_name'] or '—'}\n"
                f"    Notes : {r['notes'] or '—'} | Confiance : {r['confidence']:.0%}\n"
                f"    🔗 {FIREFLY_URL}/transactions/show/{r['tx_id']}\n"
            )

    if low_confidence:
        lines += [
            "─" * 60,
            f"⚠️  À VÉRIFIER — FAIBLE CONFIANCE ({len(low_confidence)})",
            "─" * 60,
            "Ces transactions ont été catégorisées mais méritent votre vérification.",
            "",
        ]
        for r in low_confidence:
            lines.append(
                f"  • [{r['date']}] {r['destination_name']} — {r['amount']:.2f} €\n"
                f"    Catégorie : {r['category_name'] or '—'} | Budget : {r['budget_name'] or '—'}\n"
                f"    Notes : {r['notes'] or '—'}\n"
                f"    Confiance : {r['confidence']:.0%} — {r.get('reason') or '?'}\n"
                f"    🔗 {FIREFLY_URL}/transactions/show/{r['tx_id']}\n"
            )

    if errors:
        lines += [
            "─" * 60,
            f"❌ ERREURS ({len(errors)})",
            "─" * 60,
        ]
        for e in errors:
            lines.append(f"  • ID {e['tx_id']} : {e['error']}")
        lines.append("")

    lines += [
        "=" * 60,
        f"Ce rapport a été généré automatiquement par Claude ({CLAUDE_MODEL}).",
        f"Gérez vos transactions sur : {FIREFLY_URL}",
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
# LOGGING
# ============================================================

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    if LOG_FILE:
        try:
            with open(LOG_FILE, "a") as f:
                f.write(line + "\n")
        except IOError:
            pass

# ============================================================
# MAIN
# ============================================================

def run() -> dict:
    """Run the AI categorization and return structured results.
    Called by firefly_morning_report.py — does not send any email."""
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=LOOKBACK_HOURS)

    log(f"Démarrage — analyse des {LOOKBACK_HOURS} dernières heures")

    # 1. Fetch recent transactions
    log("Récupération des transactions récentes...")
    raw = get_recent_transactions(LOOKBACK_HOURS)
    all_txs = parse_transactions(raw)
    log(f"  → {len(all_txs)} transactions récupérées")

    # 2. Filter those needing categorization
    to_process = [tx for tx in all_txs if needs_categorization(tx)]
    skipped    = [tx for tx in all_txs if not needs_categorization(tx)]
    log(f"  → {len(to_process)} à catégoriser, {len(skipped)} déjà catégorisées")

    # 3. Build merchant history lookup for category/budget reuse
    log("Récupération de l'historique des marchands...")
    merchant_history = get_merchant_history()
    log(f"  → {len(merchant_history)} marchands connus dans l'historique")

    applied = []
    errors  = []

    if to_process:
        # 4. Load Firefly reference data
        log("Chargement des catégories, budgets et comptes...")
        categories       = get_categories()
        budgets          = get_budgets()
        expense_accounts = get_expense_accounts()
        log(f"  → {len(categories)} catégories, {len(budgets)} budgets, {len(expense_accounts)} comptes")

        # 5. Send to Claude in batches of 50
        BATCH_SIZE = 50
        classifications = []
        for i in range(0, len(to_process), BATCH_SIZE):
            batch = to_process[i:i + BATCH_SIZE]
            log(f"  Envoi du lot {i // BATCH_SIZE + 1} ({len(batch)} transactions) à Claude...")
            try:
                results = classify_with_claude(batch, categories, budgets, expense_accounts)
                classifications.extend(results)
                if i + BATCH_SIZE < len(to_process):
                    time.sleep(1)
            except Exception as e:
                log(f"  ❌ Erreur lors de l'appel Claude : {e}")
                for tx in batch:
                    classifications.append({"id": tx["tx_id"], "_error": str(e)})

        result_map = {str(r.get("id")): r for r in classifications}

        # 6. Apply classifications to Firefly
        log("Application des catégorisations dans Firefly...")
        for tx in to_process:
            result = result_map.get(str(tx["tx_id"]))
            if not result:
                errors.append({"tx_id": tx["tx_id"], "error": "Pas de résultat Claude"})
                continue
            if "_error" in result:
                errors.append({"tx_id": tx["tx_id"], "error": result["_error"]})
                continue

            updates = {}
            ai_merchant     = result.get("destination_name", "").strip()
            lookup_merchant = ai_merchant or tx["merchant"]
            history_entry   = merchant_history.get(lookup_merchant.lower(), {}) if lookup_merchant else {}
            if history_entry:
                log(f"  📚 Marchand '{lookup_merchant}' trouvé dans l'historique — réutilisation de la catégorie/budget")

            if not tx["category"]:
                category = history_entry.get("category") or result.get("category_name") or None
                if category:
                    updates["category_name"] = category
            if tx["type"] == "withdrawal" and not tx["budget"]:
                budget = history_entry.get("budget") or result.get("budget_name") or None
                if budget:
                    updates["budget_name"] = budget
            if ai_merchant:
                updates["destination_name"] = ai_merchant
                existing_tags = tx.get("tags") or []
                if AI_MERCHANT_TAG not in existing_tags:
                    updates["tags"] = existing_tags + [AI_MERCHANT_TAG]
            if ENRICH_NOTES and result.get("notes"):
                updates["notes"] = result["notes"]

            if not updates:
                log(f"  ⏭ ID {tx['tx_id']} — aucun champ à mettre à jour")
                skipped.append(tx)
                continue

            try:
                patch_transaction(tx["tx_id"], updates)
                record = {
                    "tx_id":            tx["tx_id"],
                    "date":             tx["date"],
                    "amount":           tx["amount"],
                    "description":      tx["description"],
                    "destination_name": updates.get("destination_name") or tx["merchant"],
                    "category_name":    updates.get("category_name", ""),
                    "budget_name":      updates.get("budget_name", ""),
                    "notes":            updates.get("notes", ""),
                    "confidence":       float(result.get("confidence", 1.0)),
                    "reason":           result.get("reason"),
                    "from_history":     bool(history_entry),
                }
                applied.append(record)
                log(
                    f"  ✅ ID {tx['tx_id']} — {record['destination_name']} "
                    f"→ {record['category_name']} / {record['budget_name']} "
                    f"({record['confidence']:.0%})"
                )
            except Exception as e:
                errors.append({"tx_id": tx["tx_id"], "error": str(e)})
                log(f"  ❌ ID {tx['tx_id']} — erreur PATCH : {e}")

    log(f"Terminé : {len(applied)} catégorisées, {len(errors)} erreurs")

    return {
        "applied":      applied,
        "skipped":      skipped,
        "errors":       errors,
        "period_start": start.strftime("%Y-%m-%d"),
        "period_end":   now.strftime("%Y-%m-%d"),
    }


def main():
    """Standalone entry point — runs categorization and sends its own email.
    When called from firefly_morning_report.py, use run() directly instead."""
    data = run()
    applied  = data["applied"]
    errors   = data["errors"]
    skipped  = data["skipped"]

    log("Envoi du rapport par email...")
    body = build_report(applied, skipped, errors, data["period_start"], data["period_end"])
    low_conf_count = sum(1 for r in applied if r.get("confidence", 1.0) < CONFIDENCE_THRESHOLD)

    if low_conf_count > 0:
        subject = f"🤖 Firefly — {len(applied)} catégorisées, ⚠️ {low_conf_count} à vérifier"
    elif applied:
        subject = f"🤖 Firefly — {len(applied)} transaction(s) catégorisées automatiquement"
    else:
        subject = "🤖 Firefly — Aucune nouvelle transaction à catégoriser"

    send_email(subject, body)
    log("Email envoyé.")

if __name__ == "__main__":
    main()
