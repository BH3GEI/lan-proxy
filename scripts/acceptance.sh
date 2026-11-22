#!/bin/bash
# Acceptance test from a LAN client (macOS/Linux, bash). Password on stdin; output has it masked.
read -r PW
H=192.168.3.89:10800
P="http://yao:$PW@$H"
socks() { curl -s --max-time 25 --socks5-hostname "$H" --proxy-user "yao:$1" "${@:2}"; }
echo "## client $(hostname) $(ipconfig getifaddr en0 2>/dev/null || hostname -I) $(date)"
echo "## LAN client, correct password"
for u in https://www.baidu.com https://www.bilibili.com https://www.google.com/generate_204 https://www.youtube.com https://github.com; do
  curl -s -o /dev/null -w "HTTP-CONNECT $u -> %{http_code} %{time_total}s\n" --max-time 25 -x "$P" "$u"; done
for u in https://www.baidu.com https://www.google.com/generate_204; do
  socks "$PW" -o /dev/null -w "SOCKS5 $u -> %{http_code} %{time_total}s\n" "$u"; done
curl -s -o /dev/null -w "HTTP-plain http://example.com/ -> %{http_code}\n" --max-time 25 -x "$P" http://example.com/
echo "exit IP seen by foreign site api.ipify.org (HTTP): $(curl -s --max-time 20 -x "$P" https://api.ipify.org)"
echo "exit IP seen by CN site myip.ipip.net (SOCKS5): $(socks "$PW" https://myip.ipip.net | tr -d '\n')"
echo "## wrong password"
curl -s -o /dev/null -w "HTTP wrong password -> CONNECT status %{http_connect}\n" --max-time 15 -x "http://yao:wrongpass@$H" https://www.baidu.com
socks wrongpass -o /dev/null https://www.baidu.com; echo "SOCKS5 wrong password -> curl exit $? (97 = proxy handshake failed)"
echo "## NAS itself and internal networks (expect 403 / CONNECT 403 / SOCKS exit 97)"
for t in http://192.168.3.89/ http://192.168.3.89:5000/ http://127.0.0.1:8080/ http://172.28.4.67:8080/ http://172.18.0.1/ http://192.168.3.2/ http://169.254.169.254/ 'http://[::1]/' http://catyao.heiyu.space/; do
  curl -s -o /dev/null -w "HTTP $t -> %{http_code}\n" --max-time 15 -x "$P" "$t"; done
curl -s -o /dev/null -w "CONNECT 192.168.3.89:443 -> %{http_connect}\n" --max-time 15 -x "$P" https://192.168.3.89/
socks "$PW" -o /dev/null http://192.168.3.89:5000/; echo "SOCKS5 192.168.3.89:5000 -> curl exit $?"
socks "$PW" -o /dev/null http://127.0.0.1/; echo "SOCKS5 127.0.0.1 -> curl exit $?"
echo "## other LAN device via proxy (lenovo 192.168.3.84:22 banner)"
curl -s --max-time 6 -x "$P" -p telnet://192.168.3.84:22 </dev/null | head -c 30; echo
echo "## non-LAN source: proxy port via the LazyCat network name catyao.heiyu.space"
curl -s -o /dev/null -w "catyao.heiyu.space:10800 -> http %{http_code}, curl exit %{exitcode}\n" --max-time 10 -x "http://yao:$PW@catyao.heiyu.space:10800" https://www.baidu.com
