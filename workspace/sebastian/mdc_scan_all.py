import requests
import json

def mdc_scan_all(hashes_arr):
    """MetaDefender Cloud API interface"""
    endpoint = "https://api.metadefender.com/v4/hash"
    header = {'apikey': "SET_API_KEY", "includescandetails": "1"}
    payload = {
        "hash": hashes_arr
    }
    payload_json_string = json.dumps(payload)
    req = requests.post(endpoint, headers=header, data=payload_json_string)
    if req.status_code == 200:
        res = req.json()
        data = res["data"]
        hash_results = {}
        for record in data:
            total_avs = len(record["scan_details"])
            print("total_avs: ", total_avs)
            total_detected_avs = record["total_detected_avs"]
            print("total_detected_avs: ", total_detected_avs)
            label = str(total_detected_avs) + "/" + str(total_avs)
            hash_results[record["hash"]] = label
        return hash_results
    elif req.status_code == 429:
        return 429
    else:
        return None

hashes_arr = ["8F7920DA1D52B06A61D7A41C51D595AC", "AA73B43084E93E741552E5B9C8DEE457"]
mdc_scan_all(hashes_arr)