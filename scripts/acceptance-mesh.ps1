"battery: " + (Get-CimInstance Win32_Battery).EstimatedChargeRemaining + "%"
Resolve-DnsName catyao.heiyu.space -Type AAAA -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress
$M="catyao.heiyu.space:10800"
foreach ($u in "https://www.baidu.com","https://www.google.com/generate_204") { $c = curl.exe -s -o NUL -w "%{http_code}" --max-time 25 -x "http://$M" $u; "HTTP via mesh $u -> $c" }
$c = curl.exe -s -o NUL -w "%{http_code}" --max-time 25 --socks5-hostname $M https://www.google.com/generate_204; "SOCKS5 via mesh google -> $c"
$c = curl.exe -s -o NUL -w "%{http_code}" --max-time 15 -x "http://$M" http://192.168.3.89:5000/; "HTTP via mesh NAS:5000 -> $c"
