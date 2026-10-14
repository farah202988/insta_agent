"""Teste WhatsApp sans passer par Instagram.  Lance :  python test_whatsapp_service.py"""
from dotenv import load_dotenv

load_dotenv()

import whatsapp_service as ws  # noqa: E402

print("Modèle :", ws.current_template())
print("Configuré :", ws.is_configured())
result = ws.send_test()
ws.log_result(result, "TEST")
print(result)