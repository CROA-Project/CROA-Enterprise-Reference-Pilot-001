import requests

try:
    resp = requests.get("https://github.com/CROA-Project/CROA-Enterprise-Reference-Pilot-001/releases/tag/v0.1.0")
    print(resp.status_code)
    import re
    m = re.search(r"<title>(.*?)</title>", resp.text)
    if m:
        print("TITLE:", m.group(1))
except Exception as e:
    print(e)
