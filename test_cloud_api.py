import os
import httpx
from dotenv import load_dotenv

load_dotenv()

token = os.getenv("WHATSAPP_ACCESS_TOKEN")
phone_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
to = "".join(ch for ch in os.getenv("WHATSAPP_ADMIN_PHONE", "") if ch.isdigit())

version = os.getenv("WHATSAPP_API_VERSION", "v26.0")

body = {
    "name": "hello_world",
    "language": {
        "code": "en_US"
    }
}

url = f"https://graph.facebook.com/{version}/{phone_id}/messages"

response = httpx.post(
    url,
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    },
    json={
        "messaging_product": "whatsapp",
        "to": to,
        "type": "template",
        "template": body
    },
    timeout=20
)

print("STATUS:", response.status_code)
print("RESPONSE:", response.text)

if response.status_code == 200:
    print("✅ Message envoyé avec succès !")
else:
    print("❌ Erreur lors de l'envoi.")
    