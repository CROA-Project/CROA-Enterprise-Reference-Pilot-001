import requests

r1 = requests.get("http://localhost:8001/evidence")
print("Evidence count:", len(r1.json().get('chain', [])))
