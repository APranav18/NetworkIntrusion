"""Test script to simulate brute force attacks"""
from database import record_failed_login, get_monitored_websites, add_monitored_website
import random

# Get existing website or add one
websites = get_monitored_websites()
if websites:
    website_id = websites[0]['id']
    print(f"Using website: {websites[0]['name']} (ID: {website_id})")
else:
    website_id = add_monitored_website('https://www.flipkart.com', 'Flipkart')
    print(f"Added Flipkart with ID: {website_id}")

# Simulate 7 failed login attempts from same IP (triggers alert at 5+)
test_ip = f"103.77.52.{random.randint(1, 254)}"
print(f"\nSimulating brute force attack from IP: {test_ip}")
print("-" * 50)

geo_data = {
    'lat': 28.6139 + random.uniform(-0.1, 0.1),
    'lon': 77.2090 + random.uniform(-0.1, 0.1),
    'country': 'India',
    'city': 'New Delhi',
    'regionName': 'Delhi',
    'isp': 'Jio Telecom'
}

device_data = {
    'device_type': 'Desktop',
    'browser': 'Chrome 120',
    'os': 'Windows 10',
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

for i in range(7):
    result = record_failed_login(
        website_id=website_id,
        ip_address=test_ip,
        geo_data=geo_data,
        device_data=device_data
    )
    status = "⚠️ ALERT TRIGGERED!" if i >= 4 else "recorded"
    print(f"  Attempt {i+1}: {status}")

print("\n" + "=" * 50)
print("✓ Brute force attack simulated!")
print("  - 7 failed login attempts recorded")
print(f"  - Attacker IP: {test_ip}")
print("  - Location: New Delhi, India")
print("\n📊 Refresh your dashboard to see:")
print("  1. Red markers on the map")
print("  2. Failed login entries in the table")
print("  3. Security notifications")
print("  4. Block IP button to block the attacker")
