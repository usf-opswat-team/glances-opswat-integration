import requests

def mdc_api(hash: str):
        """MetaDefender Cloud API interface"""
        api_base_url = "https://api.metadefender.com/v4/"
        header = {'apikey': ""}
        endpoint_path = f'/hash/{hash}'
        endpoint = f"{api_base_url}{endpoint_path}"
        req = requests.get(endpoint, headers=header)
        if req.status_code == 200:
            res = req.json()
            total_avs = res["scan_results"]["total_avs"]
            total_detected_avs = res["scan_results"]["total_detected_avs"]
            return ( f'{total_detected_avs}/{total_avs}')
        elif req.status_code == 429:
            return "Already surpassed the API"
        
        else:
            return "x"

print(mdc_api("5e2bf57d3f40c4b6df69daf1936cb766f832374b4fc0259a7cbff06e2f70f269"))

