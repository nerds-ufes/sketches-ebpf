#!/bin/bash

echo "[*] Fase 1 — ICMP (ping)"
ping -c 20 -i 0.2 8.8.8.8

echo "[*] Fase 2 — HTTP GET (10 requisições paralelas)"
for i in $(seq 1 10); do
    curl -s -o /dev/null http://httpbin.org/get &
done
wait

echo "[*] Fase 3 — Download 10MB"
wget -q --show-progress http://speedtest.tele2.net/10MB.zip -O /tmp/test.zip

echo "[*] Tráfego concluído — rode ./stop.sh para o relatório"