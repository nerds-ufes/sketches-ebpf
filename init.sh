#!/bin/bash
IFACE=${1:-enp0s3}

sudo ./cms_user $IFACE &
CMS_PID=$!
echo $CMS_PID > /tmp/cms.pid
echo "[*] CMS iniciado (PID $CMS_PID) na interface $IFACE"
echo "[*] Rode ./test.sh para gerar tráfego"
echo "[*] Rode ./stop.sh para encerrar e ver o relatório"