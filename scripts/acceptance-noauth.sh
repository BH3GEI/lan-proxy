#!/bin/bash
# No-auth acceptance from a LAN client (bash). No credentials needed; the wrong-password check uses a dummy.
H=192.168.3.89:10800
echo "## client $(hostname) $(hostname -I 2>/dev/null | cut -d' ' -f1) $(date)"
echo "## no credentials"
for u in https://www.baidu.com https://www.bilibili.com https://www.google.com/generate_204 https://github.com; do
  curl -s -o /dev/null -w "HTTP-CONNECT $u -> %{http_code} %{time_total}s\n" --max-time 25 -x "http://$H" "$u"; done
curl -s -o /dev/null -w "HTTP-plain http://example.com/ -> %{http_code}\n" --max-time 25 -x "http://$H" http://example.com/
for u in https://www.baidu.com https://www.google.com/generate_204; do
  curl -s -o /dev/null -w "SOCKS5 $u -> %{http_code} %{time_total}s\n" --max-time 25 --socks5-hostname "$H" "$u"; done
echo "exit IP, foreign site (HTTP): $(curl -s --max-time 20 -x "http://$H" https://api.ipify.org)"
echo "exit IP, CN site (SOCKS5): $(curl -s --max-time 20 --socks5-hostname "$H" https://myip.ipip.net | tr -d '\n')"
echo "## wrong password is refused, not downgraded"
curl -s -o /dev/null -w "HTTP wrong password -> CONNECT %{http_connect}\n" --max-time 15 -x "http://nobody:wrongpass@$H" https://www.baidu.com
curl -s -o /dev/null --max-time 15 --socks5-hostname "$H" --proxy-user nobody:wrongpass https://www.baidu.com; echo "SOCKS5 wrong password -> curl exit $? (97 = refused)"
echo "## NAS itself and internal networks, no credentials (expect 403 / CONNECT 403 / SOCKS exit 97)"
for t in http://192.168.3.89/ http://192.168.3.89:5000/ http://192.168.3.4/ http://127.0.0.1:8080/ http://172.17.0.1/ http://192.168.3.2/ http://169.254.169.254/ 'http://[::1]/'; do
  curl -s -o /dev/null -w "HTTP $t -> %{http_code}\n" --max-time 15 -x "http://$H" "$t"; done
curl -s -o /dev/null -w "CONNECT 192.168.3.89:443 -> %{http_connect}\n" --max-time 15 -x "http://$H" https://192.168.3.89/
curl -s -o /dev/null --max-time 15 --socks5-hostname "$H" http://192.168.3.89:5000/; echo "SOCKS5 192.168.3.89:5000 -> curl exit $?"
curl -s -o /dev/null --max-time 15 --socks5-hostname "$H" http://127.0.0.1/; echo "SOCKS5 127.0.0.1 -> curl exit $?"
echo "## non-LAN source: LazyCat network name"
curl -s -o /dev/null -w "catyao.heiyu.space:10800 -> http %{http_code}, curl exit %{exitcode}\n" --max-time 10 -x "http://catyao.heiyu.space:10800" https://www.baidu.com
