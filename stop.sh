#!/bin/bash

if [ ! -f /tmp/cms.pid ]; then
    echo "[!] PID não encontrado — o CMS está rodando?"
    exit 1
fi

CMS_PID=$(cat /tmp/cms.pid)
echo "[*] Encerrando CMS (PID $CMS_PID)..."
sudo kill -SIGINT $CMS_PID
wait $CMS_PID 2>/dev/null
rm -f /tmp/cms.pid /tmp/test.zip