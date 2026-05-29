import requests

targets = [
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:8081"
]

for target in targets:

    try:
        response = requests.get(target)

        print(f"{target} -> {response.status_code}")

    except Exception as e:
        print(f"{target} -> ERROR: {e}")