
import requests
import base64
import json

#API key for VirusTotal
VT_API_KEY = "da4c55b552c0c3e834f2d6307c6ebb37f63e3eb3b85f176437e39b0255d484c2"

#header send request
headers = {
    "x-apikey": VT_API_KEY
}

def scan_url(url):
    #encode url to base64
    url_bytes = url.encode('utf-8')
    url_id = base64.urlsafe_b64encode(url_bytes).decode('utf-8').strip('=')
    
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    response = requests.get(vt_url, headers=headers)
    
    if (response.status_code == 200):
        data = response.json()
        return data
    else:
        print(f"Error:", response.status_code)
        return None
    
#test
if __name__ == "__main__":
    test_url = "http://testsafebrowsing.appspot.com/s/phishing.html"
    
    result = scan_url(test_url)
    
    if result:
        stats = result["data"]["attributes"]["last_analysis_stats"]
        print(json.dumps(stats, indent=4))
