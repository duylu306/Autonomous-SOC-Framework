import json
import os

eve_path = '../suricata_logs/eve.json'
ti_path = 'ti_feed.yml'

malicious_ips = set()

# 1. Đọc log Suricata và gom IP tấn công
if os.path.exists(eve_path):
    with open(eve_path, 'r') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                if event.get('event_type') == 'alert':
                    # Lấy IP nguồn của kẻ tấn công
                    malicious_ips.add(event.get('src_ip'))
            except:
                continue

# 2. Đọc file TI Feed hiện tại để kiểm tra trùng lặp
existing_ips = set()
if os.path.exists(ti_path):
    with open(ti_path, 'r') as f:
        for line in f:
            if ':' in line:
                # Lấy IP bỏ qua dấu nháy kép
                ip = line.split(':')[0].strip(' "\'')
                existing_ips.add(ip)

# 3. Ghi IP mới vào "Sổ đen"
new_ips = malicious_ips - existing_ips
if new_ips:
    with open(ti_path, 'a') as f:
        for ip in new_ips:
            f.write(f'"{ip}": "AUTO_BANNED_BY_SURICATA"\n')
    print(f"[+] Đã thêm {len(new_ips)} IP độc hại mới vào {ti_path}!")
else:
    print("[-] Không có IP mới nào.")