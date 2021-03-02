import requests
import hashlib
import json

from credentials import API_KEY

headers = {
    'x-apikey': API_KEY,
}

file = ""

with open(file, "rb") as f:
    bytes = f.read()
    hash = hashlib.sha256(bytes).hexdigest()

response = requests.get('https://www.virustotal.com/api/v3/files/'+hash, headers=headers)

print(response.content)