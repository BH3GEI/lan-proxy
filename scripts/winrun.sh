#!/bin/sh
# Run a PowerShell script on a Windows host over ssh: scripts/winrun.sh <host> <script-file>
h=$1; f=$2
enc=$(iconv -f UTF-8 -t UTF-16LE "$f" | base64 | tr -d '\n')
ssh "$h" "powershell -NoProfile -EncodedCommand $enc"
