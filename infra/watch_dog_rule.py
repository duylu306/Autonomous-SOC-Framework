from elasticsearch import Elasticsearch
import threading
import urllib3
import os

# Tắt rác cảnh báo SSL của urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cấu hình đường dẫn đến Threat Intel Feed
TI_PATH = 'ti_feed.yml'

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "SoC_Admin_Password_123!"),
    verify_certs=False
)

# Bộ nhớ lưu trữ các mục tiêu đã bị cách ly để tránh spam
contained_targets_memory = set()

def contain_target(target, rule_name):
    print(f"[SOAR KÍCH HOẠT] Đang cách ly mục tiêu: {target} (Lý do: {rule_name})")
    
    # Chỉ thực hiện thêm vào ti_feed nếu mục tiêu là địa chỉ IP (thường từ rule DNS Tunneling)
    # Kiểm tra định dạng IP cơ bản (có dấu chấm và chữ số)
    if "." in str(target) and any(char.isdigit() for char in str(target)):
        existing_ips = set()
        
        # 1. Đọc file TI Feed hiện tại để kiểm tra trùng lặp
        if os.path.exists(TI_PATH):
            with open(TI_PATH, 'r') as f:
                for line in f:
                    if ':' in line:
                        ip = line.split(':')[0].strip(' "\'')
                        existing_ips.add(ip)

        # 2. Nếu IP chưa tồn tại trong danh sách, thực hiện ghi đè/thêm mới
        if target not in existing_ips:
            try:
                with open(TI_PATH, 'a') as f:
                    reason = f"AUTO_BANNED_BY_WATCHDOG_{rule_name.upper().replace(' ', '_')}"
                    f.write(f'"{target}": "{reason}"\n')
                print(f"[+] Đã tự động thêm IP {target} vào {TI_PATH}!")
            except Exception as e:
                print(f"[!] Lỗi khi ghi vào file TI Feed: {e}")

def process_targets(targets, rule_name):
    # Lọc ra những mục tiêu MỚI chưa từng bị ban
    new_targets = list(filter(lambda t: t not in contained_targets_memory, targets))
    # Cập nhật sổ tay
    contained_targets_memory.update(new_targets)
    # Thực thi cách ly
    list(map(lambda t: contain_target(t, rule_name), new_targets))

def run_watchdog():
    try:
        # --- RULE 1: SYSMON PARENT-CHILD ---
        # Query tìm kiếm các tiến trình cha đáng ngờ spawning shell
        query_sysmon = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "terms": {
                                "process.parent.name": [
                                    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                                    "explorer.exe", "wmiprvse.exe", "wscript.exe", "cscript.exe",
                                    "mshta.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe",
                                    "powershell.exe", "schtasks.exe", "taskeng.exe", "services.exe", "svchost.exe"
                                ]
                            }
                        },
                        {
                            "terms": {
                                "process.name": [
                                    "powershell.exe", "cmd.exe", "mshta.exe", "rundll32.exe",
                                    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
                                    "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe"
                                ]
                            }
                        }
                    ],
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-10y"}}}
                    ]
                }
            }
        }

        res_sysmon = es.search(index="winlogbeat-*", body=query_sysmon)
        infected_hosts = [hit['_source'].get('host', {}).get('name', 'UNKNOWN') for hit in res_sysmon['hits']['hits']]
        process_targets(set(filter(lambda h: h != 'UNKNOWN', infected_hosts)), "Suspicious Parent-Child Process")

        # --- RULE 2: ZEEK DNS TUNNELING ---
        # Query phát hiện DNS Tunneling dựa trên Entropy và độ dài nhãn
        query_dns = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"match": {"type": "zeek"}},
                        {"range": {"dns.question.entropy": {"gte": 3.5}}},
                        {"range": {"dns.question.label_length": {"gte": 50}}}
                    ],
                    "filter": [{"range": {"@timestamp": {"gte": "now-15m"}}}]
                }
            },
            "aggs": {
                "malicious_ips": {
                    "terms": {
                        "field": "source_ip.keyword",
                        "min_doc_count": 20
                    }
                }
            }
        }
        res_dns = es.search(index="zeek-data-*", body=query_dns)
        bad_ips = [bucket['key'] for bucket in res_dns.get('aggregations', {}).get('malicious_ips', {}).get('buckets', [])]
        process_targets(bad_ips, "DNS Tunneling (High Entropy)")

    except Exception as e:
        print(f"Lỗi kết nối ES: {e}")

    threading.Timer(10.0, run_watchdog).start()

print(" SOAR Watchdog đang chạy đa luồng (Sysmon + Zeek)...")
run_watchdog()