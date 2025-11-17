
import base64
import requests
import vt
import os
import csv
import time

API_KEY = 'cc3c00b8268e5c123e3aa8d11465a10e805bbfacfe7a1a001df8f483504e26c2'

def scan_url(url_to_scan):
    headers = {'x-apikey': API_KEY}

    # Step 1: Submit the URL for scanning
    scan_url = 'https://www.virustotal.com/api/v3/urls'
    data = {'url': url_to_scan}
    response = requests.post(scan_url, headers=headers, data=data)
    response.raise_for_status()

    # Step 2: Encode URL to get its ID
    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip('=')
    report_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'

    # Step 3: Retrieve the report
    report_response = requests.get(report_url, headers=headers)
    report_response.raise_for_status()
    report_data = report_response.json()

    # Step 4: Print summary stats
    stats = report_data['data']['attributes']['last_analysis_stats']
    print(f"\n🔍 Scan summary for {url_to_scan}:")
    
    print(f"  Harmless:   {stats['harmless']}")
    print(f"  Suspicious: {stats['suspicious']}")
    print(f"  Undetected: {stats['undetected']}")

    # Step 5: Print vendor-specific results
    print("\n🧪 Vendor analysis:")
    results = report_data['data']['attributes']['last_analysis_results']
    for vendor, result in results.items():
        category = result['category']
        result_text = result.get('result', 'Clean')
        print(f"  {vendor}: {result_text} ({category})")
        # Step 6: Print final pattern line
    total_vendors = len(results)
    total_malicious = stats['malicious']
    print(f"\n📊 Pattern: {total_malicious} / {total_vendors} security vendors flagged as malicious")


# Main loop
while True:
    url_input = input("\n🌐 Enter a URL to scan (e.g., https://example.com): ").strip()
    if not url_input:
        print("⚠️ Please enter a valid URL.")
        continue

    try:
        scan_url(url_input)
    except Exception as e:
        print(f"❌ Error during scan: {e}")

    again = input("\n🔁 Would you like to scan another URL? (yes/no): ").strip().lower()
    if again != 'yes':
        print("✅ Scan session ended.")
        break