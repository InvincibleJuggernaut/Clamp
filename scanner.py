import requests
import hashlib
import json
from colorama import init, Fore, Back, Style

from credentials import API_KEY

headers = {
    'x-apikey': API_KEY,
}

def find_hash(file):
    with open(file, "rb") as f:
        bytes = f.read()
        hash = hashlib.sha256(bytes).hexdigest()
        return hash

def search_vt(hash):
    response = requests.get('https://www.virustotal.com/api/v3/files/'+hash, headers=headers)
    resp = json.loads(response.content.decode('utf-8'))
    try:
        if(resp['error']['code']=='NotFoundError'):
            resp = "NoHistory"
    except:
        resp = resp
    return resp

def get_stats(resp):  
    print("Probabilities for file type : ")
    for x in resp['data']['attributes']['trid']:
        file_type=x['file_type']
        probability=x['probability']
        print(str(file_type) + " - " + str(probability))

    size = resp['data']['attributes']['size']
    times_submitted = resp['data']['attributes']['times_submitted']
    last_modification_date = resp['data']['attributes']['last_modification_date']
    name = resp['data']['attributes']['names']

    print()
    print("Name : ", name)
    print("Size : ", size)
    print("Times submitted : ", times_submitted)
    print("Last modification date : ", last_modification_date)
    print()

    for x in resp['data']['attributes']['last_analysis_results']:
        engine_name = x
        category = resp['data']['attributes']['last_analysis_results'][x]['category']
        result = resp['data']['attributes']['last_analysis_results'][x]['result']
        if(category!='undetected' and category!='type-unsupported' and category!='timeout' and category!='failure'):
            print(str(engine_name) +" - "+ Fore.RED + str(category) + Style.RESET_ALL+ " - "+ str(result))
        else:
            print(str(engine_name) +" - "+ str(category) +" - "+ str(result))