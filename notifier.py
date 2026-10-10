"""Notifications WhatsApp pour le commerçant (via le service gratuit CallMeBot).

Configuration dans .env :
    NOTIFY_WHATSAPP=+21612345678:1234567
(numéro avec indicatif pays, deux-points, clé API reçue de CallMeBot)
Plusieurs personnes : sépare-les par des virgules.
    NOTIFY_WHATSAPP=+21612345678:1234567,+21698765432:7654321
"""
import os
import threading
import time

import httpx

API_URL = "https://api.callmebot.com/whatsapp.php"


def _recipients():
    out = []
    for part in os.getenv("NOTIFY_WHATSAPP", "").split(","):
        part = part.strip()
        if ":" in part:
            phone, key = part.split(":", 1)
            phone, key = phone.strip(), key.strip()
            if phone and key:
                out.append((phone, key))
    return out


def is_configured():
    return bool(_recipients())


def _send_one(phone, apikey, text):
    """Envoie un message (2 essais). Ne lève jamais d'erreur : une notification ratée
    ne doit jamais empêcher d'enregistrer une commande."""
    for attempt in range(2):
        try:
            r = httpx.get(
                API_URL,
                params={"phone": phone, "text": text, "apikey": apikey},
                timeout=20,
            )
            print("WHATSAPP", phone, r.status_code, r.text[:100].replace("\n", " "))
            if r.status_code == 200:
                return True
        except Exception as e:
            print("WHATSAPP ERREUR :", e)
        if attempt == 0:
            time.sleep(2)
    return False


def notify_owner(text):
    """Envoie la notification en arrière-plan (ne ralentit pas la réponse au client)."""
    recipients = _recipients()
    if not recipients:
        print("(notification WhatsApp non configurée : ajoute NOTIFY_WHATSAPP dans .env)")
        return False
    for phone, key in recipients:
        threading.Thread(target=_send_one, args=(phone, key, text), daemon=True).start()
    return True


def send_test(text):
    """Envoi immédiat, pour tester la configuration. Retourne (succès, nombre de destinataires)."""
    recipients = _recipients()
    if not recipients:
        return False, 0
    results = [_send_one(phone, key, text) for phone, key in recipients]
    return all(results), len(recipients)


def dashboard_link():
    base = os.getenv("PUBLIC_URL", "").rstrip("/")
    return "{}/dashboard/orders".format(base) if base else ""


def order_message(order_id, total, quantity, size, product_name, color,
                  customer_name, phone, address, payment_method):
    lines = [
        "🛍️ *Nouvelle commande {}*".format(order_id),
        "{} × {} {}, pointure {}".format(quantity, product_name, color, size),
        "Total : *{} TND* ({})".format(total, payment_method),
        "Client : {} · {}".format(customer_name, phone),
        "Adresse : {}".format(address),
    ]
    link = dashboard_link()
    if link:
        lines.append(link)
    return "\n".join(lines)


def handoff_message(instagram_id, reason, last_message):
    lines = [
        "⚠️ *Un client attend une réponse humaine*",
        "Raison : {}".format(reason),
        "Dernier message : « {} »".format(last_message),
        "Instagram ID : {}".format(instagram_id),
        "Réponds-lui dans Instagram.",
    ]
    link = dashboard_link()
    if link:
        lines.append(link)
    return "\n".join(lines)