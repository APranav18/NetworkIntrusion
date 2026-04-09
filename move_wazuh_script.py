import sys
import shutil
import os

# Move wazuh_integration.py to wazuh/ directory if not already there
src = os.path.join(os.path.dirname(__file__), 'wazuh_integration.py')
dst = os.path.join(os.path.dirname(__file__), 'wazuh', 'wazuh_integration.py')

if os.path.exists(src):
    shutil.move(src, dst)
    print(f"Moved wazuh_integration.py to {dst}")
else:
    print("wazuh_integration.py already moved or not found.")
