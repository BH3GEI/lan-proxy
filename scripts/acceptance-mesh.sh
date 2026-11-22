#!/bin/bash
# LazyCat-network acceptance from a client logged into the LazyCat client (bash, a few minutes of curl).
M=catyao.heiyu.space:10800
L=192.168.3.89:10800
echo "## client $(hostname) $(date); battery: $(pmset -g batt 2>/dev/null | tail -1 | cut -f2)"
echo "catyao.heiyu.space resolves to: $(dscacheutil -q host -a name catyao.heiyu.space 2>/dev/null | grep address | head -1)"
echo "## via LazyCat network ($M), no credentials"
for u in https://www.baidu.com https://www.google.com/generate_204 http://example.com/; do
  curl -s -o /dev/null -w "HTTP $u -> %{http_code} %{time_total}s\n" --max-time 25 -x "http://$M" "$u"; done
for u in https://www.baidu.com https://www.google.com/generate_204; do
  curl -s -o /dev/null -w "SOCKS5 $u -> %{http_code} %{time_total}s\n" --max-time 25 --socks5-hostname "$M" "$u"; done
echo "exit IP, foreign (HTTP): $(curl -s --max-time 20 -x "http://$M" https://api.ipify.org)"
curl -s -o /dev/null -w "wrong password via mesh -> CONNECT %{http_connect}\n" --max-time 15 -x "http://nobody:wrongpass@$M" https://www.baidu.com
echo "## NAS itself and internal targets via mesh (expect 403 / SOCKS exit 97)"
for t in http://192.168.3.89/ http://192.168.3.89:5000/ http://127.0.0.1:8080/ 'http://[fc03:1136:3836:1325:d659:7981:993a:0]/' http://catyao.heiyu.space/ http://172.17.0.1/; do
  curl -s -o /dev/null -w "HTTP $t -> %{http_code}\n" --max-time 15 -x "http://$M" "$t"; done
curl -s -o /dev/null --max-time 15 --socks5-hostname "$M" http://192.168.3.89:5000/; echo "SOCKS5 192.168.3.89:5000 via mesh -> curl exit $?"
echo "## LAN listener still works"
curl -s -o /dev/null -w "HTTP via LAN https://www.baidu.com -> %{http_code}\n" --max-time 25 -x "http://$L" https://www.baidu.com
curl -s -o /dev/null -w "HTTP via LAN http://192.168.3.89/ -> %{http_code}\n" --max-time 15 -x "http://$L" http://192.168.3.89/
