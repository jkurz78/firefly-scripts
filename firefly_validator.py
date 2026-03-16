#!/usr/bin/env python3
"""
Firefly III — Transaction Validator
=====================================
Small Flask server that handles one-click VERIFIED tag addition
from links embedded in the morning report email.

Security model:
  - Each link contains a HMAC-SHA256 signature over (tx_id + expiry timestamp)
  - Links expire after VALIDATOR_TOKEN_EXPIRY_HOURS (default 24h)
  - An attacker who intercepts the email cannot forge a link for a different
    transaction, nor reuse an expired link
  - The signing secret never leaves the server

Configuration (environment variables):
  FIREFLY_URL                  — e.g. https://firefly.feucherolles.net
  FIREFLY_TOKEN                — Personal Access Token
  VALIDATOR_SECRET             — random secret for HMAC signing (min 32 chars)
  VALIDATOR_TOKEN_EXPIRY_HOURS — link validity in hours (default 24)

Deploy:
  - Run via docker-compose as firefly-validator service
  - Reverse proxy validator.feucherolles.net → port 8089
"""

import hashlib
import hmac
import os
import time
from datetime import datetime

import requests
from flask import Flask, abort, render_template_string, request

# ============================================================
# CONFIGURATION — from environment variables
# ============================================================

FIREFLY_URL        = os.environ["FIREFLY_URL"]         # internal Docker URL for API calls
FIREFLY_PUBLIC_URL = os.environ.get("FIREFLY_PUBLIC_URL", FIREFLY_URL)  # public URL for links
FIREFLY_TOKEN = os.environ["FIREFLY_TOKEN"]
VALIDATOR_SECRET = os.environ["VALIDATOR_SECRET"].encode("utf-8")
EXPIRY_HOURS  = int(os.environ.get("VALIDATOR_TOKEN_EXPIRY_HOURS", "24"))
VERIFIED_TAG  = os.environ.get("VERIFIED_TAG", "VERIFIED")

# ============================================================
# HMAC HELPERS
# ============================================================

def make_sig(tx_id: str, expires: int) -> str:
    """Generate HMAC-SHA256 signature for (tx_id, expires)."""
    msg = f"{tx_id}:{expires}".encode("utf-8")
    return hmac.new(VALIDATOR_SECRET, msg, hashlib.sha256).hexdigest()


def make_validate_url(tx_id: str, base_url: str, expiry_hours: int = None) -> str:
    """Generate a signed validation URL valid for expiry_hours hours."""
    if expiry_hours is None:
        expiry_hours = EXPIRY_HOURS
    expires = int(time.time()) + expiry_hours * 3600
    sig     = make_sig(str(tx_id), expires)
    return f"{base_url}/validate?tx={tx_id}&exp={expires}&sig={sig}"


def verify_token(tx_id: str, expires: str, sig: str) -> tuple[bool, str]:
    """Verify token validity. Returns (ok, error_message)."""
    try:
        exp_int = int(expires)
    except (ValueError, TypeError):
        return False, "Token invalide."
    if time.time() > exp_int:
        exp_dt = datetime.fromtimestamp(exp_int).strftime("%d/%m/%Y %H:%M")
        return False, f"Ce lien a expiré le {exp_dt}."
    expected = make_sig(str(tx_id), exp_int)
    if not hmac.compare_digest(expected, sig):
        return False, "Signature invalide — ce lien ne peut pas être utilisé."
    return True, ""

# ============================================================
# FIREFLY API
# ============================================================

def get_transaction(tx_id: str) -> dict | None:
    """Fetch a transaction from Firefly. Returns the first split or None."""
    resp = requests.get(
        f"{FIREFLY_URL}/api/v1/transactions/{tx_id}",
        headers={"Authorization": f"Bearer {FIREFLY_TOKEN}",
                 "Accept": "application/json"},
        timeout=10,
    )
    if not resp.ok:
        return None
    data = resp.json()
    splits = data.get("data", {}).get("attributes", {}).get("transactions", [])
    return splits[0] if splits else None


def add_verified_tag(tx_id: str) -> tuple[bool, str]:
    """Add VERIFIED tag to a transaction. Returns (success, error_message)."""
    # Fetch current tags
    resp = requests.get(
        f"{FIREFLY_URL}/api/v1/transactions/{tx_id}",
        headers={"Authorization": f"Bearer {FIREFLY_TOKEN}",
                 "Accept": "application/json"},
        timeout=10,
    )
    if not resp.ok:
        return False, f"Impossible de récupérer la transaction (HTTP {resp.status_code})."

    data   = resp.json()
    splits = data.get("data", {}).get("attributes", {}).get("transactions", [])
    if not splits:
        return False, "Transaction introuvable."

    current_tags = splits[0].get("tags") or []
    if VERIFIED_TAG in current_tags:
        return False, f"La transaction est déjà marquée « {VERIFIED_TAG} »."

    new_tags = current_tags + [VERIFIED_TAG]

    # PUT with minimal payload — only transaction_journal_id and tags required
    journal_id = splits[0].get("transaction_journal_id")
    put_resp = requests.put(
        f"{FIREFLY_URL}/api/v1/transactions/{tx_id}",
        headers={"Authorization": f"Bearer {FIREFLY_TOKEN}",
                 "Accept": "application/json",
                 "Content-Type": "application/json"},
        json={
            "apply_rules": False,
            "fire_webhooks": False,
            "transactions": [{
                "transaction_journal_id": journal_id,
                "tags": new_tags,
            }],
        },
        timeout=10,
    )
    if not put_resp.ok:
        return False, f"Impossible de mettre à jour la transaction (HTTP {put_resp.status_code})."

    return True, ""

# ============================================================
# HTML TEMPLATES
# ============================================================

BASE_STYLE = """
  body { margin:0; padding:0; background:#f4f6f9;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
         color:#2d3748; }
  .wrap { max-width:480px; margin:40px auto; padding:16px; }
  .header { background:#4a7fa5; border-radius:8px; padding:20px;
            text-align:center; margin-bottom:20px; }
  .header h1 { color:#fff; font-size:18px; margin:8px 0 4px; }
  .header p  { color:rgba(255,255,255,0.75); font-size:13px; margin:0; }
  .card { background:#fff; border-radius:8px; border:1px solid #dde3ea;
          padding:20px; margin-bottom:16px; }
  .card h2 { font-size:15px; margin:0 0 12px; color:#2d3748; }
  .tx-row { display:flex; justify-content:space-between; align-items:baseline;
            flex-wrap:wrap; gap:4px; margin-bottom:4px; }
  .tx-name { font-size:14px; font-weight:600; }
  .tx-amount { font-size:14px; font-family:'Courier New',monospace; }
  .tx-date { font-size:12px; color:#718096; }
  .btn { display:inline-block; padding:10px 20px; border-radius:6px;
         font-size:14px; font-weight:600; text-decoration:none;
         text-align:center; margin-top:12px; }
  .btn-primary { background:#4a7fa5; color:#fff; }
  .btn-secondary { background:#f4f6f9; color:#2d3748;
                   border:1px solid #dde3ea; }
  .status-ok  { background:#f0fff4; border-left:3px solid #68d391;
                border-radius:4px; padding:12px; color:#276749;
                font-weight:600; font-size:14px; }
  .status-err { background:#fff5f5; border-left:3px solid #fc8181;
                border-radius:4px; padding:12px; color:#c53030;
                font-weight:600; font-size:14px; }
  .status-warn{ background:#fffaf0; border-left:3px solid #f6ad55;
                border-radius:4px; padding:12px; color:#c05621;
                font-weight:600; font-size:14px; }
"""

CONFIRM_PAGE = """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Valider la transaction</title>
<style>{{ style }}</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>Firefly III — Validation</h1>
    <p>Famille Kurz</p>
  </div>
  <div class="card">
    <h2>Transaction à valider</h2>
    <div class="tx-row">
      <span class="tx-name">{{ name }}</span>
      <span class="tx-amount">€&nbsp;{{ amount }}</span>
    </div>
    <div class="tx-date">{{ date }}</div>
    <p style="font-size:13px;color:#718096;margin:12px 0 0">
      Confirmer l'ajout du tag <strong>{{ verified_tag }}</strong> à cette transaction ?
    </p>
    <form method="POST" action="/validate">
      <input type="hidden" name="tx"  value="{{ tx_id }}">
      <input type="hidden" name="exp" value="{{ exp }}">
      <input type="hidden" name="sig" value="{{ sig }}">
      <button type="submit"
              style="display:block;width:100%;padding:12px;margin-top:16px;
                     background:#4a7fa5;color:#fff;border:none;border-radius:6px;
                     font-size:15px;font-weight:700;cursor:pointer">
        ✅ Valider cette transaction
      </button>
    </form>
  </div>
</div>
</body>
</html>"""

RESULT_PAGE = """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
<style>{{ style }}</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>Firefly III — Validation</h1>
    <p>Famille Kurz</p>
  </div>
  <div class="card">
    <div class="{{ status_class }}">{{ message }}</div>
    {% if tx_url %}
    <a href="{{ tx_url }}" class="btn btn-primary"
       style="display:block;margin-top:16px;text-align:center">
      Voir la transaction dans Firefly III
    </a>
    {% endif %}
    <button onclick="window.close()"
            style="display:block;width:100%;padding:10px;margin-top:10px;
                   background:#f4f6f9;color:#2d3748;border:1px solid #dde3ea;
                   border-radius:6px;font-size:14px;font-weight:600;cursor:pointer">
      Fermer cette fenêtre
    </button>
  </div>
</div>
</body>
</html>"""

# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)


@app.route("/validate", methods=["GET"])
def validate_get():
    """Show confirmation page before applying the tag."""
    tx_id   = request.args.get("tx", "")
    expires = request.args.get("exp", "")
    sig     = request.args.get("sig", "")

    ok, err = verify_token(tx_id, expires, sig)
    if not ok:
        return render_template_string(
            RESULT_PAGE,
            style=BASE_STYLE, title="Lien invalide",
            status_class="status-err", message=f"❌ {err}",
            tx_url=None,
        ), 403

    tx = get_transaction(tx_id)
    if not tx:
        return render_template_string(
            RESULT_PAGE,
            style=BASE_STYLE, title="Transaction introuvable",
            status_class="status-err",
            message="❌ Transaction introuvable dans Firefly III.",
            tx_url=None,
        ), 404

    # Check if already validated
    if VERIFIED_TAG in (tx.get("tags") or []):
        return render_template_string(
            RESULT_PAGE,
            style=BASE_STYLE, title="Déjà validée",
            status_class="status-warn",
            message=f"⚠️ Cette transaction est déjà marquée « {VERIFIED_TAG} ».",
            tx_url=f"{FIREFLY_PUBLIC_URL}/transactions/show/{tx_id}",
        ), 200

    name   = (tx.get("destination_name") or tx.get("description") or "(inconnu)")
    amount = f"{float(tx.get('amount', 0)):,.2f}"
    date   = (tx.get("date") or "")[:10]

    return render_template_string(
        CONFIRM_PAGE,
        style=BASE_STYLE,
        name=name, amount=amount, date=date,
        verified_tag=VERIFIED_TAG,
        tx_id=tx_id, exp=expires, sig=sig,
    )


@app.route("/validate", methods=["POST"])
def validate_post():
    """Apply the VERIFIED tag after form submission."""
    tx_id   = request.form.get("tx", "")
    expires = request.form.get("exp", "")
    sig     = request.form.get("sig", "")

    ok, err = verify_token(tx_id, expires, sig)
    if not ok:
        return render_template_string(
            RESULT_PAGE,
            style=BASE_STYLE, title="Lien invalide",
            status_class="status-err", message=f"❌ {err}",
            tx_url=None,
        ), 403

    success, err = add_verified_tag(tx_id)
    if not success:
        status_class = "status-warn" if "déjà marquée" in err else "status-err"
        icon = "⚠️" if "déjà marquée" in err else "❌"
        return render_template_string(
            RESULT_PAGE,
            style=BASE_STYLE, title="Erreur",
            status_class=status_class, message=f"{icon} {err}",
            tx_url=f"{FIREFLY_PUBLIC_URL}/transactions/show/{tx_id}",
        ), 200

    return render_template_string(
        RESULT_PAGE,
        style=BASE_STYLE, title="Transaction validée",
        status_class="status-ok",
        message=f"✅ Tag « {VERIFIED_TAG} » ajouté avec succès.",
        tx_url=f"{FIREFLY_PUBLIC_URL}/transactions/show/{tx_id}",
    )


@app.route("/health")
def health():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8089, debug=False)
