#!/bin/bash

if [ -z "$1" ]; then
  echo " Cách dùng: ./soar_playbook.sh <tên_file.pcap>"
  echo " Ví dụ: ./soar_playbook.sh shark2.pcapng"
  exit 1
fi

PCAP_FILE=$1


echo "Mục tiêu: $PCAP_FILE"
echo "------------------------------------------------"

echo "[1/3]  Suricata đang quét chữ ký..."
docker compose exec suricata sh -c "> /var/log/suricata/eve.json; > /var/log/suricata/fast.log"
docker compose exec suricata suricata -r /pcap_to_process/$PCAP_FILE -l /var/log/suricata
echo " Suricata quét xong!"

echo "[2/3]  Đang cập nhật Threat Intel Feed..."
python3 auto_ban.py
echo " Cập nhật sổ đen xong!"

echo "[3/3] Zeek đang phân tích metadata mạng..."
sudo rm -rf ../zeek_logs/*.log
docker compose exec --workdir /zeek_logs zeek zeek -C -r /pcap_to_process/$PCAP_FILE LogAscii::use_json=T
echo " Zeek phân tích xong!"
