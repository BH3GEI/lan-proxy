#!/bin/sh
# Cross-compile on a build machine (default mini3lan), then package with lzc-cli locally.
set -eu
cd "$(dirname "$0")/.."
HOST=${BUILD_HOST:-mini3lan}
rsync -a --delete --exclude pkg/dist --exclude pkg/content --exclude vendor --exclude .git ./ "$HOST":~/lanproxy-build/
ssh "$HOST" 'zsh -lc "cd ~/lanproxy-build && go vet ./... && nice -n 10 go test -count=1 ./... && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=\"-s -w\" -o pkg/content/lanproxy ./cmd/lanproxy"'
rsync -a "$HOST":~/lanproxy-build/pkg/content/lanproxy pkg/content/lanproxy
chmod 755 pkg/content/lanproxy
# mihomo, pinned by version and SHA256 (same release as wxbrief's), and the bundled China rule sets.
MH=vendor/mihomo-linux-amd64-compatible-v1.19.33.gz
echo "386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6  $MH" | shasum -a 256 -c -
gunzip -c "$MH" > pkg/content/mihomo && chmod 755 pkg/content/mihomo
mkdir -p pkg/content/rules
cp vendor/geosite_cn.mrs vendor/geoip_cn.mrs pkg/content/rules/
cp pkg/supervise.sh pkg/content/supervise.sh
mkdir -p pkg/dist
cd pkg && lzc-cli project build -f lzc-build.yml
