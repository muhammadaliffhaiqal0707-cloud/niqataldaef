import requests

API_KEY = '6971449e011dc30b7a89f882db1bc582e420684c8e1155b64a879b06aee5a9aad639d1deacd00d84'  # Replace with your actual API key

def scan_ip(ip_address):
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    # Step 1: Get summary info from /check
    check_url = 'https://api.abuseipdb.com/api/v2/check'
    check_params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    check_response = requests.get(check_url, headers=headers, params=check_params)
    check_response.raise_for_status()
    check_data = check_response.json()['data']

    print(f"\n🔍 AbuseIPDB Report for {ip_address}:")
    print(f"  Abuse Confidence Score: {check_data['abuseConfidenceScore']}")
    print(f"  Total Reports (Database): {check_data['totalReports']}")
    print(f"  Last Reported:            {check_data['lastReportedAt']}")
    print(f"  Country:                  {check_data['countryCode']}")
    print(f"  ISP:                      {check_data['isp']}")
    print(f"  Domain:                   {check_data['domain']}")
    print(f"  Usage Type:               {check_data['usageType']}")
    print(f"  Hostnames:                {', '.join(check_data['hostnames']) if check_data['hostnames'] else 'None'}")

    # Step 2: Get full report history from /reports
    reports_url = 'https://api.abuseipdb.com/api/v2/reports'
    reports_params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
        'limit': '10'
    }

    reports_response = requests.get(reports_url, headers=headers, params=reports_params)
    reports_response.raise_for_status()
    reports_data = reports_response.json()
    report_list = reports_data.get('data', [])

    print("\n📂 IP Abuse Reports:")
    print(f"  Total Reports in Database: {check_data['totalReports']}")
    print(f"  Reports Retrieved (Last 90 Days): {len(report_list)}")
    if not report_list:
        print("  No abuse reports found.")
    else:
        for i, report in enumerate(report_list[:3], start=1):
            print(f"\n  Report #{i}")
            print(f"    Date Reported : {report['reportedAt']}")
            print(f"    Categories    : {report['categories']}")
            print(f"    Comment       : {report['comment'] or 'No comment'}")

# Main loop
while True:
    ip_input = input("\n🌐 Enter an IP address to scan (e.g., 8.8.8.8): ").strip()
    if not ip_input:
        print("⚠️ Please enter a valid IP address.")
        continue

    try:
        scan_ip(ip_input)
    except Exception as e:
        print(f"❌ Error during scan: {e}")

    again = input("\n🔁 Would you like to scan another IP? (yes/no): ").strip().lower()
    if again != 'yes':
        print("✅ Scan session ended.")
        break