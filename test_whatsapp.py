"""Teste ta configuration WhatsApp : lance  python test_whatsapp.py"""
from dotenv import load_dotenv

load_dotenv()

import notifier  # noqa: E402

if not notifier.is_configured():
    print("NOTIFY_WHATSAPP est absent ou mal écrit dans .env")
    print("Format attendu : NOTIFY_WHATSAPP=+21612345678:1234567")
else:
    ok, n = notifier.send_test("✅ Test : les notifications de ta boutique fonctionnent !")
    print("Message envoyé à {} numéro(s).".format(n) if ok else
          "Échec : vérifie le numéro, la clé API, et relis la réponse de CallMeBot ci-dessus.")