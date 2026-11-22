# lanproxy — 懒猫局域网代理

服务局域网和懒猫组网设备的 HTTP（含 CONNECT）+ SOCKS5 代理，打包为懒猫应用 `bh3gei.lzcapp.lanproxy`。Go，无第三方依赖。

## 结构
- `cmd/lanproxy` — 入口：`lanproxy proxy`（代理）与 `lanproxy admin`（管理网页）。
- `internal/core/policy.go` — 来源与目标判定、网卡与路由枚举。
- `internal/core/proxy.go` — 同端口 HTTP/SOCKS5、认证与限速、连接限制、日志、状态。
- `internal/web` — 管理网页（`index.html` 内嵌）与接口。
- `pkg/` — lpk 打包；`pkg/build.sh` 在构建机（默认 mini3lan）测试并交叉编译，本机只执行 `lzc-cli project build`。

## 运行方式
- `proxy` service：`network_mode: host`，uid 1000，只用 `tcp4` 绑定 NAS 局域网 IPv4（默认路由网卡的地址），默认端口 10800；「懒猫组网访问」打开时（默认），另用 `tcp6` 只绑定 NAS 的懒猫组网地址（启动时和每 30 秒枚举：fc00::/8 内唯一一个前缀 /8–/64 的网卡地址，即 heiyu-0；找到多个则不监听）。
- `admin` service：普通容器网络，经懒猫登录访问，代码要求 `X-HC-User-Role: ADMIN`；启动时以 root 创建 `/lzcapp/var/data` 并交给 uid 1000，随后降权。
- 两者只通过 `/lzcapp/var/data` 下的文件交换：`config.json`（admin 写，proxy 每秒检查内容并热加载）、`status.json`（proxy 写）、`conn.jsonl`（proxy 写，4 MB 轮转一次）。

## 判定规则
- 来源：按连接到的本机地址区分。连到局域网地址的，来源须在局域网网段内；连到组网地址的，来源须在该网卡的组网网段内，且回程路由经组网网卡。两种都不能是 NAS 自身的任何地址，容器网络（172.x、fd00::/8）和公网来源一律拒绝，在握手前关闭连接。
- 认证：「局域网免密码」打开时（默认），以上两类来源不带认证即可使用；带了账号密码的照常校验，错误密码拒绝并计入限速。
- 目标：域名先解析；任一结果被拒则整个请求被拒；随后直接连接检查过的 IP。拒绝 NAS 所有网卡的全部地址（每 30 秒重新枚举）、回环、局域网以外的私有和保留网段（容器、懒猫内网、CGNAT 等）、链路本地、组播、广播、经由非局域网网卡路由的地址，以及「额外禁止目标」（默认 192.168.3.2，即运行在 NAS 上的 LZCWrt）。IPv4 映射的 IPv6 地址先归一化。
- 认证：每个账号存 PBKDF2-SHA256（12 万次）哈希；同一来源 10 分钟内失败 10 次封禁 15 分钟。
- 资源：总并发 1024、每来源 256、握手 20 秒、连接上游 10 秒、隧道空闲 15 分钟、请求头 16 KB；容器内存 256 MB / 1 核（proxy），128 MB / 0.5 核（admin）。
