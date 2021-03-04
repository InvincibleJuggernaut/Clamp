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

resp = json.loads(response.content.decode('utf-8'))


print(resp['data']['attributes']['trid'][0])
print(resp['data']['attributes']['trid'][1])

print(resp['data']['attributes']['names'])
print(resp['data']['attributes']['last_modification_date'])
print(resp['data']['attributes']['type_tag'])
print(resp['data']['attributes']['times_submitted'])
print(resp['data']['attributes']['size'])
