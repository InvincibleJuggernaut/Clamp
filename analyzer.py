from scanner import find_hash, search_vt, get_stats

file = ''

hash = find_hash(file)
resp = search_vt(hash)

if(resp=="NoHistory"):
    print("This appears to be an undiscovered file")
else:
    get_stats(resp)