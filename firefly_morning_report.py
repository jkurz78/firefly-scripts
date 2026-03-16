#!/usr/bin/env python3
"""
Firefly III Morning Report — Orchestrator
==========================================
Runs every morning (recommended: 06:15) and sends a single consolidated email
covering all overnight activity:

  1. Imported transactions per account (via AutoImport tag)
  2. Account balance warnings (below configurable per-account thresholds)
  3. AI categorization results (from firefly_ai_categorize.py)
  4. Fraud detection alerts (from firefly_fraud_detection.py)

Both sub-scripts must be in the same directory as this file (or on PYTHONPATH).
Disable ENABLE_MAIL_REPORT on the importer-auto container — this script
replaces those emails.

Usage:
  python3 /volume1/docker/firefly/firefly_morning_report.py

Scheduling (DSM Task Scheduler — daily at 06:15):
  python3 /volume1/docker/firefly/firefly_morning_report.py
"""

import base64
import hashlib
import hmac as _hmac
import importlib.util
import io
import os
import smtplib
import sys
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

FIREFLY_URL                  = _cfg.FIREFLY_URL
FIREFLY_TOKEN                = _cfg.FIREFLY_TOKEN
AUTO_IMPORT_TAG              = _cfg.AUTO_IMPORT_TAG
IMPORT_LOG_LOOKBACK_HOURS    = _cfg.IMPORT_LOG_LOOKBACK_HOURS
IMPORTER_LOG_FILE            = _cfg.IMPORTER_LOG_FILE
IMPORTER_ERROR_KEYWORDS      = _cfg.IMPORTER_ERROR_KEYWORDS
IMPORTER_ERROR_IGNORE_PATTERNS = _cfg.IMPORTER_ERROR_IGNORE_PATTERNS
MONITORED_ACCOUNTS           = _cfg.MONITORED_ACCOUNTS
LOW_BALANCE_THRESHOLDS       = _cfg.LOW_BALANCE_THRESHOLDS
LOW_BALANCE_DEFAULT          = _cfg.LOW_BALANCE_DEFAULT
SETTLE_DELAY                 = _cfg.SETTLE_DELAY
SMTP_HOST                    = _cfg.SMTP_HOST
SMTP_PORT                    = _cfg.SMTP_PORT
SMTP_USER                    = _cfg.SMTP_USER
SMTP_PASS                    = _cfg.SMTP_PASS
SMTP_FROM                    = _cfg.SMTP_FROM_MORNING_REPORT
SMTP_TO                      = _cfg.SMTP_TO
MAIL_ENCRYPTION              = _cfg.MAIL_ENCRYPTION
CHART_LOOKBACK_DAYS          = _cfg.CHART_LOOKBACK_DAYS
VALIDATOR_URL                = _cfg.VALIDATOR_URL
VALIDATOR_SECRET             = _cfg.VALIDATOR_SECRET
VALIDATOR_TOKEN_EXPIRY_HOURS = _cfg.VALIDATOR_TOKEN_EXPIRY_HOURS
SCRIPT_DIR                   = _cfg.SCRIPT_DIR
CATEGORIZE_PATH              = _os.path.join(SCRIPT_DIR, "firefly_ai_categorize.py")
FRAUD_PATH                   = _os.path.join(SCRIPT_DIR, "firefly_fraud_detection.py")

# ============================================================
# DYNAMIC IMPORT HELPERS
# ============================================================

def load_module(name: str, path: str):
    """Dynamically load a Python script as a module."""
    spec   = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

# ============================================================
# FIREFLY API
# ============================================================

SESSION = requests.Session()
SESSION.headers.update({
    "Authorization": f"Bearer {FIREFLY_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
})

def make_validate_url(tx_id) -> str:
    """Generate a signed HMAC-SHA256 validation URL valid for VALIDATOR_TOKEN_EXPIRY_HOURS."""
    expires = int(time.time()) + VALIDATOR_TOKEN_EXPIRY_HOURS * 3600
    msg     = f"{tx_id}:{expires}".encode("utf-8")
    sig     = _hmac.new(VALIDATOR_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"{VALIDATOR_URL}/validate?tx={tx_id}&exp={expires}&sig={sig}"

# Firefly III logo — pre-processed (black background removed, resized to 80px)
_FIREFLY_LOGO_B64 = "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"


def get_firefly_logo_b64() -> str:
    """Return the embedded Firefly III logo as base64 PNG."""
    return _FIREFLY_LOGO_B64


def read_importer_log(hours: int) -> dict:
    """Read the mounted importer-auto (Laravel) log file and extract recent entries.
    Laravel log format: [2026-03-11 05:00:28] production.LEVEL: message
    Returns a dict with 'available' (bool), 'errors' (list), 'last_lines' (list)."""
    result = {"available": False, "errors": [], "last_lines": [], "log_path": IMPORTER_LOG_FILE}

    if not os.path.exists(IMPORTER_LOG_FILE):
        return result

    result["available"] = True
    # Only consider log entries from today — errors from previous days are irrelevant
    today_str = datetime.now().strftime("%Y-%m-%d")
    cutoff = datetime.now() - timedelta(hours=hours)

    try:
        with open(IMPORTER_LOG_FILE, "r", errors="replace") as f:
            lines = f.readlines()

        recent_lines = []
        for line in lines:
            # Laravel timestamps: [2026-03-11 05:00:28]
            try:
                if line.startswith("["):
                    ts = datetime.strptime(line[1:20], "%Y-%m-%d %H:%M:%S")
                    if ts >= cutoff and ts.strftime("%Y-%m-%d") == today_str:
                        recent_lines.append(line.rstrip())
                elif recent_lines:
                    # continuation line of a recent entry
                    recent_lines.append(line.rstrip())
            except ValueError:
                if recent_lines:
                    recent_lines.append(line.rstrip())

        result["last_lines"] = recent_lines[-30:]

        for line in recent_lines:
            line_lower = line.lower()
            # Only flag lines that match an error keyword...
            if not any(kw in line_lower for kw in IMPORTER_ERROR_KEYWORDS):
                continue
            # ...and are not known false positives
            if any(ignore in line_lower for ignore in IMPORTER_ERROR_IGNORE_PATTERNS):
                continue
            result["errors"].append(line.rstrip())

    except IOError as e:
        result["available"] = False
        result["errors"] = [f"Impossible de lire le fichier log : {e}"]

    return result


def get_imported_transactions(run_date: str) -> list:
    """Fetch transactions whose AutoImport tag matches today's date.
    Tag format: "AutoImport on YYYY-MM-DD @ HH:MM"
    We match the prefix "AutoImport on YYYY-MM-DD" so time doesn't matter."""
    tag_prefix = f"{AUTO_IMPORT_TAG} on {run_date}"
    transactions = []
    page  = 1
    # Fetch yesterday + today to cover any timezone edge cases
    start = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    end   = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    while True:
        resp = SESSION.get(
            f"{FIREFLY_URL}/api/v1/transactions",
            params={"start": start, "end": end, "page": page, "limit": 100},
        )
        resp.raise_for_status()
        data = resp.json()
        for tx in data.get("data", []):
            for split in tx.get("attributes", {}).get("transactions", []):
                tags = split.get("tags") or []
                if any(t.startswith(tag_prefix) for t in tags):
                    transactions.append({
                        "id":          tx.get("id", ""),
                        "account":     split.get("source_name", ""),
                        "description": split.get("description", ""),
                        "amount":      float(split.get("amount", 0)),
                        "date":        (split.get("date") or "")[:10],
                        "type":        split.get("type", ""),
                    })
        meta = data.get("meta", {}).get("pagination", {})
        if page >= meta.get("total_pages", 1):
            break
        page += 1

    return transactions

def get_account_balances() -> list:
    """Fetch all asset accounts with their current balance."""
    accounts = []
    page = 1
    while True:
        resp = SESSION.get(
            f"{FIREFLY_URL}/api/v1/accounts",
            params={"type": "asset", "page": page},
        )
        resp.raise_for_status()
        data = resp.json()
        for acc in data.get("data", []):
            attrs = acc.get("attributes", {})
            accounts.append({
                "id":       acc.get("id", ""),
                "name":     attrs.get("name", ""),
                "balance":  float(attrs.get("current_balance", 0)),
                "currency": attrs.get("currency_code", "EUR"),
                "active":   attrs.get("active", True),
                "type":     attrs.get("account_type", ""),
            })
        meta = data.get("meta", {}).get("pagination", {})
        if page >= meta.get("total_pages", 1):
            break
        page += 1
    return [a for a in accounts if a["active"] and
            (not MONITORED_ACCOUNTS or a["name"] in MONITORED_ACCOUNTS)]

# ============================================================
# BALANCE CHART HELPERS
# ============================================================

def get_account_transactions(account_id: str, days: int) -> list:
    """Fetch transactions for one account over the last N days."""
    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    end   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    txs   = []
    page  = 1
    while True:
        resp = SESSION.get(
            f"{FIREFLY_URL}/api/v1/accounts/{account_id}/transactions",
            params={"start": start, "end": end, "page": page, "limit": 100},
        )
        if not resp.ok:
            break
        data = resp.json()
        txs.extend(data.get("data", []))
        meta = data.get("meta", {}).get("pagination", {})
        if page >= meta.get("total_pages", 1):
            break
        page += 1
    return txs


def build_daily_balances(current_balance: float, transactions: list, days: int) -> list:
    """Reconstruct daily closing balances by walking backwards from today.
    Returns list of (date_str, balance) sorted oldest→newest."""
    from collections import defaultdict

    # Sum net daily movements (positive = money in, negative = money out)
    daily_delta = defaultdict(float)
    for tx in transactions:
        for split in tx.get("attributes", {}).get("transactions", []):
            date = split.get("date", "")[:10]
            amount = float(split.get("amount", 0))
            tx_type = split.get("type", "")
            # withdrawal / transfer_out → negative, deposit / transfer_in → positive
            if tx_type in ("withdrawal", "transfer"):
                daily_delta[date] -= amount
            elif tx_type in ("deposit",):
                daily_delta[date] += amount

    today = datetime.now(timezone.utc).date()
    dates = [(today - timedelta(days=i)) for i in range(days)]
    dates.sort()

    # Walk forward: start from (current_balance - sum of all deltas)
    # then add each day's delta
    base = current_balance
    for d in dates:
        base -= daily_delta.get(d.strftime("%Y-%m-%d"), 0.0)

    balances = []
    running = base
    for d in dates:
        running += daily_delta.get(d.strftime("%Y-%m-%d"), 0.0)
        balances.append((d.strftime("%Y-%m-%d"), running))

    return balances


def generate_chart(name: str, daily_balances: list, threshold: float,
                   currency: str) -> str:
    """Generate a small balance evolution chart, return as base64 PNG."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        from datetime import date as date_type
    except ImportError:
        return ""

    dates    = [datetime.strptime(d, "%Y-%m-%d").date() for d, _ in daily_balances]
    balances = [b for _, b in daily_balances]

    fig, ax = plt.subplots(figsize=(5, 2.2))
    fig.patch.set_facecolor("#f8f9fa")
    ax.set_facecolor("#f8f9fa")

    # Line + fill
    ax.plot(dates, balances, color="#2c7be5", linewidth=2, zorder=3)
    ax.fill_between(dates, balances, alpha=0.15, color="#2c7be5")

    # Threshold line
    if threshold and threshold > 0:
        ax.axhline(y=threshold, color="#e63757", linewidth=1,
                   linestyle="--", alpha=0.8, label=f"Seuil {threshold:.0f}")

    # Formatting
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m"))
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=max(1, len(dates)//6)))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha="right", fontsize=7)
    ax.yaxis.set_tick_params(labelsize=7)
    ax.yaxis.set_major_formatter(
        matplotlib.ticker.FuncFormatter(lambda x, _: f"{x:,.0f}")
    )
    ax.set_title(name, fontsize=8, fontweight="bold", pad=4, color="#333")
    ax.grid(axis="y", linestyle=":", alpha=0.5, color="#ccc")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#ddd")
    ax.spines["bottom"].set_color("#ddd")

    plt.tight_layout(pad=0.5)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def build_charts(accounts: list) -> dict:
    """Build base64 charts for all accounts. Returns {account_name: base64_png}."""
    charts = {}
    for acc in accounts:
        acc_id = acc.get("id")
        if not acc_id:
            continue
        print(f"  → Graphique : {acc['name']}")
        try:
            txs = get_account_transactions(acc_id, CHART_LOOKBACK_DAYS)
            daily = build_daily_balances(acc["balance"], txs, CHART_LOOKBACK_DAYS)
            is_cash = acc.get("type", "") == "cash"
            threshold = LOW_BALANCE_THRESHOLDS.get(
                acc["name"], 0 if is_cash else LOW_BALANCE_DEFAULT
            )
            b64 = generate_chart(acc["name"], daily, threshold, acc["currency"])
            if b64:
                charts[acc["name"]] = b64
        except Exception as e:
            print(f"    ⚠ Erreur graphique {acc['name']}: {e}")
    return charts


# ============================================================
# HTML HELPERS
# ============================================================

# Colour palette
C_BG        = "#f4f6f9"   # page background
C_CARD      = "#ffffff"   # section card
C_HEADER    = "#4a7fa5"   # section header bar
C_HEADER_TXT= "#ffffff"
C_BORDER    = "#dde3ea"
C_TEXT      = "#2d3748"
C_MUTED     = "#718096"
C_GREEN     = "#276749"
C_GREEN_BG  = "#f0fff4"
C_RED       = "#c53030"
C_RED_BG    = "#fff5f5"
C_ORANGE    = "#c05621"
C_ORANGE_BG = "#fffaf0"
C_BLUE      = "#2c7be5"
C_BLUE_BG   = "#ebf8ff"
C_MONO      = "'Courier New', Courier, monospace"


def h(text: str) -> str:
    """HTML-escape a string."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def badge(text: str, color: str, bg: str) -> str:
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:12px;'
            f'font-size:11px;font-weight:600;color:{color};background:{bg};'
            f'white-space:nowrap">{h(text)}</span>')


def card(title: str, title_icon: str, content_html: str,
         header_extra: str = "") -> str:
    """Wrap content in a styled section card."""
    return f"""
<div style="background:{C_CARD};border-radius:8px;border:1px solid {C_BORDER};
     margin-bottom:16px;overflow:hidden">
  <div style="background:{C_HEADER};padding:10px 16px;display:flex;
       align-items:center;justify-content:space-between">
    <span style="color:{C_HEADER_TXT};font-weight:700;font-size:14px">
      {title_icon}&nbsp; {h(title)}
    </span>
    {header_extra}
  </div>
  <div style="padding:12px 16px">
    {content_html}
  </div>
</div>"""


def stat_row(label: str, value, color: str = C_TEXT,
             bold: bool = False) -> str:
    weight = "700" if bold else "400"
    return (f'<tr><td style="padding:3px 0;color:{C_MUTED};font-size:13px;'
            f'width:60%">{h(label)}</td>'
            f'<td style="padding:3px 0;color:{color};font-size:13px;'
            f'font-weight:{weight};text-align:right">{h(str(value))}</td></tr>')


def tx_link(tx_id, label: str) -> str:
    url = f"{FIREFLY_URL}/transactions/show/{tx_id}"
    return (f'<a href="{url}" style="color:{C_BLUE};text-decoration:none;'
            f'font-weight:600">{h(label)}</a>')


def alert_row(tx: dict, reason: str, is_skipped: bool = False) -> str:
    """Render one transaction alert row."""
    date  = (tx.get("date") or "")[:10]
    label = (tx.get("merchant") or tx.get("description") or "(inconnu)")
    amt   = tx.get("amount", 0)
    bg    = "#fafafa" if is_skipped else C_RED_BG
    border= C_BORDER if is_skipped else "#feb2b2"
    opacity = "opacity:0.7;" if is_skipped else ""
    return f"""
<div style="background:{bg};border-left:3px solid {border};border-radius:4px;
     padding:8px 10px;margin-bottom:6px;{opacity}">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;
       flex-wrap:wrap;gap:4px">
    <span style="font-size:13px;font-weight:600;color:{C_TEXT}">
      {tx_link(tx['id'], label)}
    </span>
    <span style="font-size:13px;color:{C_TEXT};font-family:{C_MONO};
         white-space:nowrap">€&nbsp;{amt:,.2f}</span>
  </div>
  <div style="font-size:11px;color:{C_MUTED};margin-top:2px">{h(date)}</div>
  <div style="font-size:12px;color:{C_ORANGE};margin-top:3px">⚠ {h(reason)}</div>
</div>"""


def alert_row_with_validate(tx: dict, reason: str) -> str:
    """Like alert_row but with a Validate button for AI-assigned merchant rows."""
    date   = (tx.get("date") or "")[:10]
    label  = (tx.get("merchant") or tx.get("description") or "(inconnu)")
    amt    = tx.get("amount", 0)
    v_url  = make_validate_url(tx["id"])
    return f"""
<div style="background:{C_RED_BG};border-left:3px solid #feb2b2;border-radius:4px;
     padding:8px 10px;margin-bottom:6px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;
       flex-wrap:wrap;gap:4px">
    <span style="font-size:13px;font-weight:600;color:{C_TEXT}">
      {tx_link(tx['id'], label)}
    </span>
    <span style="font-size:13px;color:{C_TEXT};font-family:{C_MONO};
         white-space:nowrap">€&nbsp;{amt:,.2f}</span>
  </div>
  <div style="font-size:11px;color:{C_MUTED};margin-top:2px">{h(date)}</div>
  <div style="font-size:12px;color:{C_ORANGE};margin-top:3px">⚠ {h(reason)}</div>
  <a href="{v_url}"
     style="display:inline-block;margin-top:8px;padding:6px 14px;
            background:#276749;color:#fff;border-radius:5px;
            font-size:12px;font-weight:700;text-decoration:none">
    ✅ Valider ce marchand
  </a>
</div>"""


# ============================================================
# HTML SECTION BUILDERS
# ============================================================

def section_imports_html(imported: list, log_info: dict, run_date: str) -> str:
    # Import table — grouped by account with collapsible transaction list
    # Group transactions by account, preserving individual tx details
    by_account_txs: dict = {}
    for tx in imported:
        acc = tx["account"] or "(compte inconnu)"
        by_account_txs.setdefault(acc, []).append(tx)

    if not by_account_txs:
        import_html = (f'<p style="color:{C_MUTED};font-size:13px;margin:4px 0">'
                       f'Aucune transaction importée.</p>')
    else:
        accordion = ""
        for acc in sorted(by_account_txs.keys()):
            txs   = by_account_txs[acc]
            count = len(txs)
            tx_rows = ""
            max_shown = 5
            for t in txs[:max_shown]:
                desc = h(t.get("description") or "(sans libellé)")
                amt  = t.get("amount", 0)
                date = h(t.get("date", ""))
                tid  = t.get("id", "")
                link = f'{FIREFLY_URL}/transactions/show/{tid}'
                tx_rows += (
                    f'<div style="display:flex;justify-content:space-between;'
                    f'align-items:baseline;padding:4px 0;'
                    f'border-top:1px solid {C_BORDER};gap:8px">'
                    f'<span style="font-size:12px;color:{C_TEXT};flex:1;min-width:0">'
                    f'<a href="{link}" style="color:{C_BLUE};text-decoration:none">'
                    f'{desc}</a>'
                    f'<span style="color:{C_MUTED};font-size:11px;margin-left:6px">{date}</span>'
                    f'</span>'
                    f'<span style="font-size:12px;font-family:{C_MONO};'
                    f'white-space:nowrap;color:{C_TEXT}">'
                    f'€&nbsp;{amt:,.2f}</span>'
                    f'</div>'
                )
            if len(txs) > max_shown:
                extra = len(txs) - max_shown
                search_link = (f'{FIREFLY_URL}/transactions/index'
                               f'?query=tag_is%3A%22{AUTO_IMPORT_TAG}%22')
                tx_rows += (
                    f'<div style="padding:6px 0;border-top:1px solid {C_BORDER}">'
                    f'<a href="{search_link}" style="font-size:12px;color:{C_BLUE};'
                    f'text-decoration:none">'
                    f'→ Voir {extra} transaction(s) supplémentaire(s) dans Firefly</a>'
                    f'</div>'
                )
            accordion += (
                f'<details style="margin-bottom:8px">'
                f'<summary style="display:flex;justify-content:space-between;'
                f'align-items:center;cursor:pointer;'
                f'padding:6px 4px;border-radius:4px;user-select:none">'
                f'<span style="font-size:13px;font-weight:600;color:{C_TEXT}">'
                f'▶ {h(acc)}</span>'
                f'<span style="font-size:13px;font-family:{C_MONO};color:{C_MUTED}">'
                f'{count}</span>'
                f'</summary>'
                f'<div style="padding:4px 4px 0 12px">{tx_rows}</div>'
                f'</details>'
            )
        total = len(imported)
        total_row = (
            f'<div style="display:flex;justify-content:space-between;'
            f'border-top:2px solid {C_BORDER};padding-top:6px;margin-top:4px">'
            f'<span style="font-size:13px;font-weight:700;color:{C_TEXT}">Total</span>'
            f'<span style="font-size:13px;font-weight:700;font-family:{C_MONO};'
            f'color:{C_TEXT}">{total}</span>'
            f'</div>'
        )
        import_html = accordion + total_row

    # Log health
    if not log_info["available"]:
        log_html = (f'<div style="background:{C_RED_BG};border-left:3px solid {C_RED};'
                    f'border-radius:4px;padding:8px 10px;margin-top:10px">'
                    f'<span style="color:{C_RED};font-weight:600;font-size:13px">'
                    f'🔴 Journal non disponible</span><br>'
                    f'<span style="color:{C_MUTED};font-size:11px">'
                    f'{h(log_info["log_path"])}</span></div>')
    elif log_info["errors"]:
        errs = "".join(
            f'<div style="font-size:11px;font-family:{C_MONO};color:{C_RED};'
            f'margin-top:3px;word-break:break-all">{h(e)}</div>'
            for e in log_info["errors"][:5]
        )
        more = (f'<div style="font-size:11px;color:{C_MUTED};margin-top:3px">'
                f'… et {len(log_info["errors"]) - 5} autre(s)</div>'
                if len(log_info["errors"]) > 5 else "")
        log_html = (f'<div style="background:{C_RED_BG};border-left:3px solid {C_RED};'
                    f'border-radius:4px;padding:8px 10px;margin-top:10px">'
                    f'<span style="color:{C_RED};font-weight:600;font-size:13px">'
                    f'🔴 {len(log_info["errors"])} erreur(s) détectée(s)</span>'
                    f'{errs}{more}</div>')
    else:
        n = len(log_info["last_lines"])
        msg = f"{n} ligne(s) récente(s)" if n else "Aucune activité récente"
        log_html = (f'<div style="background:{C_GREEN_BG};border-left:3px solid #68d391;'
                    f'border-radius:4px;padding:8px 10px;margin-top:10px">'
                    f'<span style="color:{C_GREEN};font-weight:600;font-size:13px">'
                    f'✅ Journal OK — {h(msg)}</span></div>')

    return card("Transactions importées",
                "📥",
                import_html + log_html,
                header_extra=badge(f"{AUTO_IMPORT_TAG} on {run_date}",
                                   C_HEADER_TXT, "rgba(255,255,255,0.2)"))


def section_balances_html(accounts: list, charts: dict) -> str:
    if not accounts:
        return card("Soldes des comptes", "💰",
                    f'<p style="color:{C_MUTED};font-size:13px">Aucun compte.</p>')

    rows_html = ""
    for acc in sorted(accounts, key=lambda a: a["name"]):
        balance   = acc["balance"]
        currency  = acc["currency"]
        is_cash   = acc.get("type", "") == "cash"
        threshold = LOW_BALANCE_THRESHOLDS.get(
            acc["name"], 0 if is_cash else LOW_BALANCE_DEFAULT
        )
        low = threshold > 0 and balance < threshold
        bal_color = C_RED if low else C_TEXT
        warn_html = ""
        if low:
            warn_html = (f'<div style="font-size:11px;color:{C_RED};margin-top:1px">'
                         f'⚠ Seuil : {threshold:.0f} {currency}</div>')

        chart_html = ""
        b64 = charts.get(acc["name"])
        if b64:
            chart_html = (f'<img src="data:image/png;base64,{b64}" '
                          f'style="width:100%;max-width:480px;display:block;'
                          f'margin:8px 0 4px;border-radius:4px" alt="évolution solde">')

        rows_html += f"""
<div style="border-bottom:1px solid {C_BORDER};padding:10px 0;last-child:border:none">
  <div style="display:flex;justify-content:space-between;align-items:baseline;
       flex-wrap:wrap;gap:4px">
    <span style="font-size:13px;font-weight:600;color:{C_TEXT}">{h(acc['name'])}</span>
    <span style="font-size:14px;font-weight:700;color:{bal_color};
         font-family:{C_MONO}">{balance:,.2f} {h(currency)}</span>
  </div>
  {warn_html}
  {chart_html}
</div>"""

    return card("Soldes des comptes", "💰", rows_html)


def section_categorize_html(data: dict) -> str:
    from firefly_ai_categorize import CONFIDENCE_THRESHOLD, FIREFLY_URL as FF_URL

    applied   = data["applied"]
    errors    = data["errors"]
    low_conf  = [r for r in applied if r.get("confidence", 1.0) < CONFIDENCE_THRESHOLD]
    from_hist = [r for r in applied if r.get("from_history")]

    # Summary stats
    stats = f"""
<table style="width:100%;border-collapse:collapse;margin-bottom:{'12px' if low_conf or errors else '0'}">
  {stat_row("Catégorisées", len(applied))}
  {stat_row("Faible confiance", len(low_conf),
            C_ORANGE if low_conf else C_TEXT, bold=bool(low_conf))}
  {stat_row("Depuis historique", len(from_hist))}
  {stat_row("Erreurs", len(errors),
            C_RED if errors else C_TEXT, bold=bool(errors))}
</table>"""

    detail_html = ""
    if low_conf:
        items = ""
        for r in low_conf:
            name = (r["destination_name"] or r["description"] or "(inconnu)")
            cat  = r.get("category_name") or "—"
            bud  = r.get("budget_name") or "—"
            conf = r.get("confidence", 0)
            items += f"""
<div style="background:{C_ORANGE_BG};border-left:3px solid #f6ad55;border-radius:4px;
     padding:8px 10px;margin-bottom:6px">
  <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:4px">
    <span style="font-size:13px;font-weight:600">
      {tx_link(r['tx_id'], name)}
    </span>
    <span style="font-size:13px;font-family:{C_MONO}">€&nbsp;{r['amount']:,.2f}</span>
  </div>
  <div style="font-size:11px;color:{C_MUTED};margin-top:2px">{h(r['date'])}</div>
  <div style="font-size:12px;color:{C_ORANGE};margin-top:3px">
    {h(cat)} &nbsp;|&nbsp; Budget : {h(bud)} &nbsp;|&nbsp; Confiance : {conf:.0%}
  </div>
</div>"""
        detail_html += (f'<div style="margin-bottom:8px">'
                        f'<div style="font-size:12px;font-weight:700;color:{C_ORANGE};'
                        f'margin-bottom:6px">À vérifier :</div>{items}</div>')

    if errors:
        errs = "".join(
            f'<div style="font-size:12px;color:{C_RED};margin-bottom:4px">'
            f'ID {h(str(e["tx_id"]))} — {h(e["error"])}</div>'
            for e in errors
        )
        detail_html += (f'<div style="background:{C_RED_BG};border-left:3px solid {C_RED};'
                        f'border-radius:4px;padding:8px 10px">'
                        f'<div style="font-size:12px;font-weight:700;color:{C_RED};'
                        f'margin-bottom:4px">Erreurs :</div>{errs}</div>')

    if not low_conf and not errors:
        detail_html = (f'<div style="background:{C_GREEN_BG};border-left:3px solid #68d391;'
                       f'border-radius:4px;padding:8px 10px;margin-top:8px">'
                       f'<span style="color:{C_GREEN};font-size:13px;font-weight:600">'
                       f'✅ Toutes les catégorisations sont fiables.</span></div>')

    return card("Catégorisation IA", "🤖", stats + detail_html)


FRAUD_LABELS = {
    "unusual_amounts":    ("💰", "Montants inhabituels"),
    "night_transactions": ("🌙", "Transactions nocturnes"),
    "missing_merchants":  ("🏷️",  "Marchand manquant"),
    "new_merchants":      ("🆕", "Nouveau marchand inconnu"),
    "ai_merchants":       ("🤖", "Marchand assigné par IA (non validé)"),
    "duplicates":         ("🔁", "Doublons possibles"),
    "foreign":            ("🌍", "Transactions en devise étrangère"),
}


def section_fraud_new_html(data: dict) -> str:
    """New fraud alerts only — shown at the top of the email."""
    from firefly_fraud_detection import MERCHANT_WHITELIST_FILE

    results   = data["results"]
    total_new = sum(len(v) for v in results.values())

    alerts_html = ""
    has_alerts  = False
    for key, (icon, label) in FRAUD_LABELS.items():
        items = results.get(key, [])
        if not items:
            continue
        has_alerts = True
        if key in ("ai_merchants", "new_merchants"):
            items_html = "".join(alert_row_with_validate(tx, tx.get("reason", ""))
                                 for tx in items)
        else:
            items_html = "".join(alert_row(tx, tx.get("reason", "")) for tx in items)
        alerts_html += f"""
<div style="margin-bottom:12px">
  <div style="font-size:12px;font-weight:700;color:{C_RED};margin-bottom:6px">
    {icon} {h(label)} [{len(items)}]
  </div>
  {items_html}
</div>"""

    new_merchants = results.get("new_merchants", [])
    if new_merchants:
        unique = sorted(set(tx["merchant"].lower() for tx in new_merchants if tx["merchant"]))
        ml = "".join(
            f'<div style="font-size:12px;font-family:{C_MONO};color:{C_TEXT};'
            f'padding:2px 0">{h(m)}</div>' for m in unique
        )
        alerts_html += f"""
<div style="background:{C_BLUE_BG};border-left:3px solid {C_BLUE};border-radius:4px;
     padding:8px 10px;margin-bottom:12px">
  <div style="font-size:12px;font-weight:700;color:{C_BLUE};margin-bottom:4px">
    💡 Marchands à ajouter à la liste blanche
  </div>
  <div style="font-size:11px;color:{C_MUTED};margin-bottom:4px">
    {h(MERCHANT_WHITELIST_FILE)}
  </div>
  {ml}
</div>"""

    if not has_alerts:
        alerts_html = (f'<div style="background:{C_GREEN_BG};border-left:3px solid #68d391;'
                       f'border-radius:4px;padding:8px 10px">'
                       f'<span style="color:{C_GREEN};font-size:13px;font-weight:600">'
                       f'✅ Aucune nouvelle alerte de fraude.</span></div>')

    return card("Détection de fraude", "🔍",
                alerts_html,
                header_extra=badge(f"{total_new} alerte(s)",
                                   "#fff" if total_new else C_HEADER_TXT,
                                   C_RED if total_new else "rgba(255,255,255,0.15)"))


def section_fraud_skipped_html(data: dict) -> str:
    """Already-alerted transactions — shown at the bottom for reference.
    Returns empty string if there are no previously alerted transactions."""
    results     = data["results"]
    all_results = data["all_results"]

    skipped_html = ""
    for key, (icon, label) in FRAUD_LABELS.items():
        if key in ("new_merchants", "ai_merchants"):
            continue
        all_items = all_results.get(key, [])
        new_ids   = {tx["id"] for tx in results.get(key, [])}
        skipped   = [tx for tx in all_items if tx["id"] not in new_ids]
        if skipped:
            items_html = "".join(
                alert_row(tx, tx.get("reason", ""), is_skipped=True) for tx in skipped
            )
            skipped_html += f"""
<div style="margin-bottom:12px">
  <div style="font-size:12px;font-weight:700;color:{C_MUTED};margin-bottom:6px">
    {icon} {h(label)} [{len(skipped)}]
  </div>
  {items_html}
</div>"""

    if not skipped_html:
        return ""

    return card("Fraude — déjà signalées (pour référence)", "📋", skipped_html)


# ============================================================
# EMAIL BUILDER
# ============================================================

def build_html_email(imported, log_info, accounts, charts,
                     categorize_data, fraud_data, run_date: str,
                     logo_b64: str = "") -> str:
    """Build the full HTML email."""
    import locale
    try:
        locale.setlocale(locale.LC_TIME, "fr_FR.UTF-8")
    except locale.Error:
        pass
    now_str = datetime.now().strftime("%A %d %B %Y")

    fraud_alerts = sum(len(v) for v in fraud_data["results"].values())
    log_errors   = len(log_info.get("errors", []))
    low_balance  = sum(
        1 for a in accounts
        if LOW_BALANCE_THRESHOLDS.get(
            a["name"], 0 if a.get("type") == "cash" else LOW_BALANCE_DEFAULT
        ) > 0 and a["balance"] < LOW_BALANCE_THRESHOLDS.get(
            a["name"], 0 if a.get("type") == "cash" else LOW_BALANCE_DEFAULT
        )
    )

    # Status banner colour
    if log_errors or fraud_alerts:
        banner_bg = "#c53030"
        status_icon = "🔴"
    elif low_balance:
        banner_bg = "#c05621"
        status_icon = "⚠️"
    else:
        banner_bg = "#276749"
        status_icon = "✅"

    sections = (
        section_fraud_new_html(fraud_data)
        + section_balances_html(accounts, charts)
        + section_imports_html(imported, log_info, run_date)
        + section_categorize_html(categorize_data)
        + section_fraud_skipped_html(fraud_data)
    )

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport Firefly III</title>
</head>
<body style="margin:0;padding:0;background:{C_BG};font-family:-apple-system,
     BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:{C_TEXT}">
<div style="max-width:600px;margin:0 auto;padding:12px">

  <!-- Header -->
  <div style="background:{C_HEADER};border-radius:8px;padding:16px;
       margin-bottom:16px;text-align:center">
    {'<img src="data:image/png;base64,' + logo_b64 + '" '
     'style="height:40px;margin-bottom:6px;display:block;margin-left:auto;margin-right:auto" '
     'alt="Firefly III">' if logo_b64 else
     '<div style="font-size:22px;margin-bottom:4px">🦋</div>'}
    <div style="color:#fff;font-size:17px;font-weight:700">Rapport Firefly III de la famille Kurz</div>
    <div style="color:rgba(255,255,255,0.75);font-size:13px;margin-top:2px">
      {h(now_str.capitalize())}
    </div>
  </div>

  <!-- Status bar -->
  <div style="background:{banner_bg};border-radius:6px;padding:10px 14px;
       margin-bottom:16px;display:flex;align-items:center;gap:8px">
    <span style="font-size:18px">{status_icon}</span>
    <div>
      <span style="color:#fff;font-size:13px;font-weight:600">
        {h(str(len(imported)))} transaction(s) importée(s)
      </span>
      {'&nbsp;&nbsp;·&nbsp;&nbsp;<span style="color:rgba(255,255,255,0.85);font-size:13px">' +
        str(fraud_alerts) + ' alerte(s) fraude</span>' if fraud_alerts else ''}
      {'&nbsp;&nbsp;·&nbsp;&nbsp;<span style="color:rgba(255,255,255,0.85);font-size:13px">' +
        str(low_balance) + ' solde(s) bas</span>' if low_balance else ''}
      {'&nbsp;&nbsp;·&nbsp;&nbsp;<span style="color:rgba(255,255,255,0.85);font-size:13px">' +
        str(log_errors) + ' erreur(s) importeur</span>' if log_errors else ''}
    </div>
  </div>

  {sections}

  <!-- Footer -->
  <div style="text-align:center;padding:12px 0;color:{C_MUTED};font-size:11px">
    Rapport généré automatiquement —
    <a href="{FIREFLY_URL}" style="color:{C_BLUE};text-decoration:none">Firefly III</a>
  </div>

</div>
</body>
</html>"""


def build_plaintext_email(imported, log_info, accounts,
                          categorize_data, fraud_data, run_date: str) -> str:
    """Minimal plain text fallback."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"RAPPORT FIREFLY III — {now_str}",
        "=" * 50,
        f"Transactions importées : {len(imported)}",
        f"Erreurs importeur      : {len(log_info.get('errors', []))}",
        "",
        "SOLDES :",
    ]
    for acc in sorted(accounts, key=lambda a: a["name"]):
        lines.append(f"  {acc['name']}: {acc['balance']:,.2f} {acc['currency']}")
    cat = categorize_data
    lines += [
        "",
        f"CATÉGORISATION IA : {len(cat['applied'])} transaction(s)",
        f"  Faible confiance : {sum(1 for r in cat['applied'] if r.get('confidence',1) < 0.75)}",
    ]
    total_fraud = sum(len(v) for v in fraud_data["results"].values())
    lines += [
        "",
        f"FRAUDE : {total_fraud} alerte(s) nouvelle(s)",
        "",
        f"Voir le détail sur : {FIREFLY_URL}",
    ]
    return "\n".join(lines)


def send_email(subject: str, html_body: str, plain_body: str):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM
    msg["To"]      = SMTP_TO
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body,  "html",  "utf-8"))

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
# MAIN
# ============================================================

def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Rapport matinal Firefly III")

    # 1. Load sub-scripts as modules
    print("Chargement des modules...")
    sys.path.insert(0, SCRIPT_DIR)
    categorize_mod = load_module("firefly_ai_categorize", CATEGORIZE_PATH)
    fraud_mod      = load_module("firefly_fraud_detection", FRAUD_PATH)

    # 2. Imported transactions + importer log health
    print("Récupération des transactions importées...")
    run_date = datetime.now().strftime("%Y-%m-%d")
    imported = get_imported_transactions(run_date)
    print(f"  → {len(imported)} transaction(s) importée(s)")
    print("Lecture du journal de l'importeur...")
    log_info = read_importer_log(IMPORT_LOG_LOOKBACK_HOURS)
    if not log_info["available"]:
        print(f"  ⚠ Fichier log non disponible : {log_info['log_path']}")
    elif log_info["errors"]:
        print(f"  ⚠ {len(log_info['errors'])} erreur(s) dans les logs de l'importeur")
    else:
        print(f"  ✅ Logs importeur OK ({len(log_info['last_lines'])} ligne(s) récente(s))")

    # 3. Account balances
    print("Récupération des soldes...")
    accounts = get_account_balances()
    print(f"  → {len(accounts)} comptes actifs")

    # 4. Balance charts
    print("Génération des graphiques de soldes...")
    charts = build_charts(accounts)
    print(f"  → {len(charts)} graphique(s) généré(s)")

    # 5. AI categorization
    print("Lancement de la catégorisation IA...")
    categorize_data = categorize_mod.run()

    # 6. Wait for Firefly to settle before fraud detection
    print(f"Attente de {SETTLE_DELAY}s pour que Firefly prenne en compte les modifications...")
    time.sleep(SETTLE_DELAY)

    # 7. Fraud detection
    print("Lancement de la détection de fraude...")
    fraud_data = fraud_mod.run()

    # 8. Build and send email
    print("Construction et envoi du rapport...")
    logo_b64   = get_firefly_logo_b64()
    html_body  = build_html_email(imported, log_info, accounts, charts,
                                  categorize_data, fraud_data, run_date,
                                  logo_b64=logo_b64)
    plain_body = build_plaintext_email(imported, log_info, accounts,
                                       categorize_data, fraud_data, run_date)

    fraud_alerts = sum(len(v) for v in fraud_data["results"].values())
    low_conf     = sum(1 for r in categorize_data["applied"]
                       if r.get("confidence", 1.0) < 0.75)
    low_balance  = sum(
        1 for a in accounts
        if LOW_BALANCE_THRESHOLDS.get(
            a["name"], 0 if a.get("type") == "cash" else LOW_BALANCE_DEFAULT
        ) > 0 and a["balance"] < LOW_BALANCE_THRESHOLDS.get(
            a["name"], 0 if a.get("type") == "cash" else LOW_BALANCE_DEFAULT
        )
    )

    flags = []
    if log_info.get("errors"):
        flags.append(f"🔴 erreur importeur")
    if low_balance:
        flags.append(f"💰 {low_balance} solde(s) bas")
    if fraud_alerts:
        flags.append(f"⚠️ {fraud_alerts} alerte(s) fraude")
    if low_conf:
        flags.append(f"🤖 {low_conf} à vérifier")

    subject = "Rapport Firefly III"
    if flags:
        subject += " — " + "  |  ".join(flags)

    send_email(subject, html_body, plain_body)
    print(f"Email envoyé : {subject}")


if __name__ == "__main__":
    main()
