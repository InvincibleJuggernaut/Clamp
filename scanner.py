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

for x in resp['data']['attributes']['trid']:
    file_type=x['file_type']
    probability=x['probability']
    print(str(file_type) + " - " + str(probability))

size = resp['data']['attributes']['size']
times_submitted = resp['data']['attributes']['times_submitted']
last_modification_date = resp['data']['attributes']['last_modification_date']
name = resp['data']['attributes']['names']

print("Name : ", name)
print("Size : ", size)
print("Times submitted : ", times_submitted)
print("Last modification date : ", last_modification_date)

for x in resp['data']['attributes']['last_analysis_results']:
    engine_name = x
    category = resp['data']['attributes']['last_analysis_results'][x]['category']
    result = resp['data']['attributes']['last_analysis_results'][x]['result']
    print(str(engine_name) +" - "+ str(category) +" - "+ str(result))


