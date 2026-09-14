import requests

secret = {"X-Demo-Control-Secret": "local-pilot-secret"}
body = {"demo_run_id": "demo-recording"}

r1 = requests.post("http://localhost:8001/reset", headers=secret, json=body)
print("8001:", r1.status_code)

r2 = requests.post("http://localhost:8002/reset", headers=secret, json=body)
print("8002:", r2.status_code)
