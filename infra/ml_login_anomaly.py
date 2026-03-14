from elasticsearch import Elasticsearch
import pandas as pd
from sklearn.ensemble import IsolationForest
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "SoC_Admin_Password_123!"),
    verify_certs=False
)

def trigger_alert(user):
    print(f" [ ML ALERT] Phát hiện hành vi đăng nhập dị biệt từ User: {user} -> Kích hoạt khóa tài khoản!")

def analyze_logins():
    print(" Đang thu thập và phân tích dữ liệu đăng nhập bằng AI")
    
    # Truy vấn gom nhóm (Aggregation) số lượng đăng nhập thất bại (Event ID 4625) theo từng User
    # Truy vấn gom nhóm với đuôi .keyword và bù trừ lệch múi giờ
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [{"match": {"winlog.event_id": "4625"}}],
                # Mở rộng tới now+1d để bao trọn log lệch múi giờ
                "filter": [{"range": {"@timestamp": {"gte": "now-10y", "lte": "now+1d"}}}]
            }
        },
        "aggs": {
            "users": {
                # Bắt buộc thêm .keyword khi thao tác trên index tự do
                "terms": {"field": "winlog.event_data.TargetUserName.keyword", "size": 1000}
            }
        }
    }
    try:
        res = es.search(index="winlogbeat-*", body=query)
        buckets = res.get('aggregations', {}).get('users', {}).get('buckets', [])
        
        if not buckets:
            print("[-] Chưa có đủ dữ liệu đăng nhập thất bại để phân tích.")
            return

        # 1. Rút trích dữ liệu bằng List Comprehension
        users = [b['key'] for b in buckets]
        failed_counts = [[b['doc_count']] for b in buckets] # Định dạng ma trận 2D cho scikit-learn

        # 2. Đưa vào Rừng Cô Lập (Isolation Forest)
        # contamination=0.05 nghĩa là ta giả định có khoảng 5% là kẻ tấn công
        clf = IsolationForest(contamination=0.05, random_state=42)
        predictions = clf.fit_predict(failed_counts)

        # 3. Lọc ra các điểm dị biệt (predictions == -1) bằng List Comprehension kết hợp zip
        anomalous_users = [user for user, pred in zip(users, predictions) if pred == -1]

        # 4. Thực thi hành động với hàm bậc cao map()
        list(map(trigger_alert, anomalous_users))
        
        if not anomalous_users:
            print(" Hệ thống bình thường, không có đột biến.")

    except Exception as e:
        print(f"Lỗi truy vấn ES: {e}")

if __name__ == '__main__':
    analyze_logins()