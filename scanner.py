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
        print(" "+str(file_type) + " - " + str(probability)+"%")

    size = resp['data']['attributes']['size']
    times_submitted = resp['data']['attributes']['times_submitted']
    last_modification_date = resp['data']['attributes']['last_modification_date']
    name = resp['data']['attributes']['names']

    print()
    print("Name : ")
    for x in name[0:3]:
        print(" "+x)
    print("\nSize : "+str(size)+" bytes")
    print("\nTimes submitted : ", times_submitted)
    print("\nLast modification date : ", last_modification_date)
    print()

    legitimate_count = 0
    engine_count = 0

    for x in resp['data']['attributes']['last_analysis_results']:
        engine_name = x
        engine_count += 1
        category = resp['data']['attributes']['last_analysis_results'][x]['category']
        result = resp['data']['attributes']['last_analysis_results'][x]['result']
        if(category=='malicious'):
            print(str(engine_name).ljust(25) +" - "+ Fore.RED + str(category).ljust(20) + Style.RESET_ALL+ " - "+ str(result))
        elif(category =='undetected'):
            legitimate_count += 1
            print(str(engine_name).ljust(25) +" - "+ Fore.GREEN + str(category).ljust(20) + Style.RESET_ALL+ " - "+ str(result))
        else:
            print(str(engine_name).ljust(25) +" - "+ str(category).ljust(20) +" - "+ str(result))
    
    print("\n")
    if(legitimate_count/engine_count >= 0.7):
        print(str(legitimate_count)+" out of "+str(engine_count)+" engines detected this file as legitimate")
        print("File appears to be legitimate")
    elif(legitimate_count/engine_count >=0.5 and legitimate_count/engine_count <0.7):
        print(str(legitimate_count)+" out of "+str(engine_count)+" engines detected this file as legitimate")
    else:
        print("Only "+str(legitimate_count)+" out of "+str(engine_count)+" engines detected this file as legitimate")
        print("File appears to be malware")