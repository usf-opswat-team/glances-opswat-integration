from curses import reset_prog_mode
from time import sleep
import requests

def mdc_api_upload(filepath: str):
    """MDC API Upload File, uploaded files are placed into a queue"""
    print("filepath:", filepath)
    url = "https://api.metadefender.com/v4/file"
    headers = {
        "apikey": "SET_API_KEY",
        "Content-Type": "application/octet-stream",
    }
    print(headers)
    payload = filepath

    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code == 200:
        res_json = response.json()
        data_id = res_json["data_id"]
        return mdc_api_upload_result(data_id)
    else:
        return None

def mdc_api_upload_result(data_id):
    """MDC API Upload Result gets the result of the uploaded file once it has been processed"""
    url = f"https://api.metadefender.com/v4/file/{data_id}"
    headers = {
        "apikey": "SET_API_KEY",
        "x-file-metadata": "1"
    }
    # loop 10 times
    for x in range(9):
        response = requests.request("GET", url, headers=headers)
        if response.status_code != 200:
            return None
        res_json = response.json()
        # Check if scan is still in process
        if res_json["scan_results"]["progress_percentage"] == 100:
            total_avs = res_json["scan_results"]["total_avs"]
            total_detected_avs = 0
            if "total_detected_avs" in res_json["scan_results"]:
                total_detected_avs = res_json["scan_results"]["total_detected_avs"]
            # return f'{total_detected_avs}/{total_avs}'
            print(total_avs)
            print(total_detected_avs)
            return f'{total_detected_avs}/{total_avs}'
        # wait 1 second before attempting to check scan result
        print("waiting...", res_json["scan_results"]["progress_percentage"])
        sleep(1)
    # if after 10 attempts (~10 sec) we have not retrieved data, return None
    return None

mdc_api_upload_response = mdc_api_upload("/snap/firefox/1941/usr/lib/firefox/firefox")
print(mdc_api_upload_response)
# mdc_api_upload_result("bzIyMTAyNXpqUWQ2dEl3dVlmazRxY2xzcUI")