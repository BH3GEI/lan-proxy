$H = "192.168.3.89:10800"
"## client $env:COMPUTERNAME $(Get-Date)"
foreach ($u in "https://www.baidu.com","https://www.google.com/generate_204") {
  $c = curl.exe -s -o NUL -w "%{http_code}" --max-time 25 -x "http://$H" $u; "HTTP noauth $u -> $c" }
foreach ($u in "https://www.baidu.com","https://www.google.com/generate_204") {
  $c = curl.exe -s -o NUL -w "%{http_code}" --max-time 25 --socks5-hostname $H $u; "SOCKS5 noauth $u -> $c" }
$c = curl.exe -s -o NUL -w "%{http_connect}" --max-time 15 -x "http://nobody:wrongpass@$H" https://www.baidu.com; "HTTP wrong password -> CONNECT $c"
curl.exe -s -o NUL --max-time 15 --socks5-hostname $H --proxy-user nobody:wrongpass https://www.baidu.com; "SOCKS5 wrong password -> exit $LASTEXITCODE"
foreach ($t in "http://192.168.3.89/","http://192.168.3.89:5000/","http://127.0.0.1:8080/") {
  $c = curl.exe -s -o NUL -w "%{http_code}" --max-time 15 -x "http://$H" $t; "HTTP $t -> $c" }
curl.exe -s -o NUL --max-time 15 --socks5-hostname $H http://192.168.3.89:5000/; "SOCKS5 192.168.3.89:5000 -> exit $LASTEXITCODE"
