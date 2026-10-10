"""Service WhatsApp Cloud API (Meta) : prévient le commerçant d'une nouvelle commande.

Configuration dans .env (le jeton n'est jamais écrit dans le code ni dans les logs) :
    WHATSAPP_ACCESS_TOKEN=...            (jeton permanent de l'utilisateur système)
    WHATSAPP_PHONE_NUMBER_ID=1301558863046994
    WHATSAPP_ADMIN_PHONE=+216XXXXXXXX
    WHATSAPP_TEMPLATE_NAME=hello_world   (puis new_order_notification quand Meta l'a activé)
    WHATSAPP_TEMPLATE_LANGUAGE=en_US    (puis fr)
    WHATSAPP_API_VERSION=v26.0
"""
import os
import re
import time

import httpx

# Modèles fournis par Meta, sans variable : on n'envoie alors aucun paramètre
NO_VARIABLE_TEMPLATES = {"hello_world"}

HINTS = {
    100: "Paramètre invalide : vérifie que WHATSAPP_PHONE_NUMBER_ID est bien le Phone Number ID "
         "et pas l'identifiant du compte WhatsApp Business.",
    190: "Jeton invalide ou expiré : régénère le jeton permanent de l'utilisateur système.",
    131030: "Ce numéro n'est pas dans la liste des destinataires autorisés "
            "(WhatsApp > API Setup > To > Manage phone number list).",
    132000: "Le nombre de variables ne correspond pas à ce modèle.",
    132001: "Modèle introuvable : vérifie WHATSAPP_TEMPLATE_NAME et WHATSAPP_TEMPLATE_LANGUAGE.",
    132015: "Le modèle est en pause ou désactivé par Meta.",
    132016: "Le modèle est en pause ou désactivé par Meta.",
}


def _cfg():
    return {
        "token": os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip(),
        "phone_id": os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip(),
        "to": "".join(ch for ch in os.getenv("WHATSAPP_ADMIN_PHONE", "") if ch.isdigit()),
        "template": os.getenv("WHATSAPP_TEMPLATE_NAME", "hello_world").strip(),
        "language": os.getenv("WHATSAPP_TEMPLATE_LANGUAGE", "en_US").strip(),
        "version": os.getenv("WHATSAPP_API_VERSION", "v26.0").strip(),
    }


def is_configured():
    c = _cfg()
    return bool(c["token"] and c["phone_id"] and c["to"])


def current_template():
    """Nom et langue du modèle utilisé (aucun secret)."""
    c = _cfg()
    return {"template": c["template"], "language": c["language"]}


def safe_text(text):
    """Masque le jeton dans n'importe quel texte avant de l'afficher."""
    token = _cfg()["token"]
    text = str(text)
    return text.replace(token, "***") if token else text


def clean_param(text, max_len=900):
    """Meta refuse les retours à la ligne, tabulations et séries d'espaces dans une variable."""
    text = re.sub(r"\s+", " ", str(text)).strip()
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def format_order_summary(order_id, quantity, product_name, color, size, total,
                         customer_name, phone, address):
    """Toutes les infos de la commande dans l'unique variable {{1}} du modèle."""
    return clean_param(
        "Commande {} - {} x {} {} (pointure {}) - Total : {} TND - Client : {}, {} - Adresse : {}".format(
            order_id, quantity, product_name, color, size, total, customer_name, phone, address)
    )


def _error_result(response):
    status = response.status_code
    code, message = None, ""
    try:
        err = response.json().get("error", {})
        code, message = err.get("code"), err.get("message", "")
    except Exception:
        message = response.text[:200]
    return {"ok": False, "status": status, "error_code": code,
            "error": safe_text(message), "hint": HINTS.get(code, "")}


def send_template(variable_text=None):
    """Envoie le modèle configuré. Ne lève jamais d'exception.
    Retourne {"ok": bool, "status": int|None, "message_id": str|None, "error": str|None, ...}."""
    c = _cfg()
    missing = [name for name, value in (
        ("WHATSAPP_ACCESS_TOKEN", c["token"]),
        ("WHATSAPP_PHONE_NUMBER_ID", c["phone_id"]),
        ("WHATSAPP_ADMIN_PHONE", c["to"]),
    ) if not value]
    if missing:
        return {"ok": False, "status": None,
                "error": "Variables manquantes dans .env : " + ", ".join(missing)}

    template = {"name": c["template"], "language": {"code": c["language"]}}
    if c["template"] not in NO_VARIABLE_TEMPLATES:
        template["components"] = [{
            "type": "body",
            "parameters": [{"type": "text", "text": clean_param(variable_text or "Test")}],
        }]
    payload = {"messaging_product": "whatsapp", "to": c["to"], "type": "template",
               "template": template}
    url = "https://graph.facebook.com/{}/{}/messages".format(c["version"], c["phone_id"])
    headers = {"Authorization": "Bearer " + c["token"]}

    last = {"ok": False, "status": None, "error": "échec de l'envoi"}
    for attempt in range(3):
        try:
            response = httpx.post(url, headers=headers, json=payload, timeout=20)
        except httpx.HTTPError as e:
            last = {"ok": False, "status": None,
                    "error": "connexion impossible ({})".format(type(e).__name__)}
        else:
            if response.status_code == 200:
                message_id = None
                try:
                    message_id = response.json()["messages"][0]["id"]
                except Exception:
                    pass
                return {"ok": True, "status": 200, "message_id": message_id, "error": None}
            last = _error_result(response)
            if response.status_code != 429 and response.status_code < 500:
                break  # erreur de configuration : réessayer ne servirait à rien
        if attempt < 2:
            time.sleep(attempt + 1)
    return last


def log_result(result, label="WHATSAPP"):
    if result.get("ok"):
        print(label, "OK : message envoyé", result.get("message_id") or "")
    else:
        print(label, "ECHEC", result.get("status") or "", "({})".format(result.get("error_code"))
              if result.get("error_code") else "", result.get("error", ""))
        if result.get("hint"):
            print(label, "CONSEIL :", result["hint"])


def send_order_notification(summary):
    """Envoie la notification de nouvelle commande et journalise le résultat."""
    result = send_template(summary)
    log_result(result)
    return result


def send_test():
    """Message de test : hello_world sans variable, ou une fausse commande pour un modèle personnalisé."""
    return send_template("Commande TEST - 1 x Nike Air Force 1 noir (pointure 42) - Total : 289 TND")