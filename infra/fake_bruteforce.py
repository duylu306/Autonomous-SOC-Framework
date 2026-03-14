from elasticsearch import Elasticsearch
from datetime import datetime
import urllib3

urllib3.disable_warnings()

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "SoC_Admin_Password_123!"),
    verify_certs=False
)

def inject_realistic_mock():
    print(" Đang cấy data giả lập: 50 User bình thường và 1 Kẻ tấn công")
    now_str = datetime.now().isoformat()
    
    # Hàm tạo cặp bulk action - document chuẩn của ES
    def make_bulk_pair(user):
        return [
            {"index": {"_index": "winlogbeat-mock-data"}}, 
            {"@timestamp": now_str, "winlog": {"event_id": "4625", "event_data": {"TargetUserName": user}}}
        ]

    # Tạo mảng 50 nhân viên (fail 2 lần) và 1 Admin (fail 100 lần)
    normal_users = [f"Employee_{i}" for i in range(50) for _ in range(2)]
    attacker = ["Administrator"] * 100
    
    # Gộp danh sách và trải phẳng (flatten) thành list các cặp thao tác
    all_events = normal_users + attacker
    actions = [item for user in all_events for item in make_bulk_pair(user)]
    
    # Bơm 300 document thẳng vào DB bằng 1 API call duy nhất
    es.bulk(operations=actions)
    print(" Đã tạo xong 'Khu rừng': 50 cây thường, 1 cây đột biến (Administrator).")

if __name__ == '__main__':
    inject_realistic_mock()