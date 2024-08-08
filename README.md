# Sing-box 的代理规则

这几天换 sing-box 了，真香，但是好像没好用的规则库，就自己搓了个

基本上就是 https://github.com/Loyalsoldier/v2ray-rules-dat 这个项目，只是

- 构建数据添加了我日常上不去的站
- 构建数据添加了我日常被错误重定向到国内的站
- 格式换成了 .srs

## 用法

数据都在 https://github.com/VeroFess/proxy-rules-datas/tree/data , Release 里的可能构建脚本写的有点问题，数据不是最新的，在修好之前建议别用

## 样例
### OpenWrt 路由器

这里是双线配置, proxy-hk 是香港的，不能解锁流媒体和 chatgpt, 也没 ipv6; proxy-en 是美国的啥都能干机器, 用的是 nft + dnsmasq + tproxy 方案

#### nft 配置

##### update_china_ips.sh
```
rm -rf /tmp/china_ip_list.tmp

export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

curl https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt -o /tmp/china_ip_list.tmp

if [ $? -ne 0 ]; then
    echo "Error: Failed to download china_ip_list.txt"
    exit 1
fi

echo nft delete set inet transparent_proxy direct_v4 > /etc/custom/script/china.ips
echo nft add set inet transparent_proxy direct_v4 { type ipv4_addr\\\; flags constant, interval\\\; } >> /etc/custom/script/china.ips
echo nft add element inet transparent_proxy direct_v4 { \\ >> /etc/custom/script/china.ips

for ips in `cat /tmp/china_ip_list.tmp`
do
    echo "${ips}, \\" >> /etc/custom/script/china.ips
done

echo } >> /etc/custom/script/china.ips

rm -rf /tmp/china_ip_list.tmp

unset http_proxy
unset https_proxy
```

##### update_china_ipv6_ips.sh
```
rm -rf /tmp/china_ip_list_v6.tmp

export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

curl https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt -o /tmp/china_ip_list_v6.tmp

if [ $? -ne 0 ]; then
    echo "Error: Failed to download china_ip_list.txt"
    exit 1
fi

echo nft delete set inet transparent_proxy direct_v6 > /etc/custom/script/china-ipv6.ips
echo nft add set inet transparent_proxy direct_v6 { type ipv6_addr\\\; flags constant, interval\\\; } >> /etc/custom/script/china-ipv6.ips
echo nft add element inet transparent_proxy direct_v6 { \\ >> /etc/custom/script/china-ipv6.ips

for ips in `cat /tmp/china_ip_list_v6.tmp`
do
    echo "${ips}, \\" >> /etc/custom/script/china-ipv6.ips
done

echo } >> /etc/custom/script/china-ipv6.ips

rm -rf /tmp/china_ip_list_v6.tmp

unset http_proxy
unset https_proxy
```

##### update_dnsmasq_config.sh
```
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

/etc/custom/script/gfw_list_to_dnsmasq.sh --type inet --table transparent_proxy --v4set transparent_proxy_v4 --v6set transparent_proxy_v6 --dns 8.8.8.8 --port 53 --extra-domain-file /etc/custom/config/custom-proxy.list --exclude-domain-file /etc/custom/config/custom-ignore.list --url https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt --output /etc/custom/config/dnsmasq.d/transparent_proxy.hosts

unset http_proxy
unset https_proxy
```

##### transparent_proxy
```
#!/bin/sh /etc/rc.common
# "new(er)" style init script
# Look at /lib/functions/service.sh on a running system for explanations of what other SERVICE_
# options you can use, and when you might want them.

START=81

start() {
  ip rule add fwmark 1 table 100 
  ip route add local 0.0.0.0/0 dev lo table 100

  ip -f inet6 rule add fwmark 1 table 100
  ip -6 route add local ::/0 dev lo table 100

  sh -c /etc/custom/script/china.ips
  sh -c /etc/custom/script/china-ipv6.ips

  nft add set inet transparent_proxy non_public_v4 { type ipv4_addr\; flags constant, interval\; }
  nft add set inet transparent_proxy non_public_v6 { type ipv6_addr\; flags constant, interval\; }
  nft add set inet transparent_proxy proxy_server_v4 { type ipv4_addr\; flags constant\; }
  nft add set inet transparent_proxy proxy_server_v6 { type ipv6_addr\; flags constant\; }

  nft add element inet transparent_proxy non_public_v4 { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8, 255.255.255.255/32, 224.0.0.0/4 }
  nft add element inet transparent_proxy non_public_v6 { fc00::/7, fe80::/10, ff00::/8, ::1/128, ::ffff:0:0/96 }

  nft add element inet transparent_proxy proxy_server_v4 { *** }
  nft add element inet transparent_proxy proxy_server_v6 { *** }

  # telegram 的 ip 段, https://core.telegram.org/resources/cidr.txt
  nft add element inet transparent_proxy high_priority_transparent_proxy_v4 { 91.108.56.0/22, 91.108.4.0/22, 91.108.8.0/22, 91.108.16.0/22, 91.108.12.0/22, 149.154.160.0/20, 91.105.192.0/23, 91.108.20.0/22, 185.76.151.0/24 }
  nft add element inet transparent_proxy high_priority_transparent_proxy_v6 { 2001:b28:f23d::/48, 2001:b28:f23f::/48, 2001:67c:4e8::/48, 2001:b28:f23c::/48, 2a0a:f280::/32 }

  # cloudflare warp
  nft add element inet transparent_proxy high_priority_transparent_proxy_v4 { 162.159.192.0/24, 162.159.193.0/24, 162.159.197.0/24 }
  nft add element inet transparent_proxy high_priority_transparent_proxy_v6 { 2606:4700:100::/48, 2606:4700:102::/48 }
  
  # cloudflare cloudflared
  # region1.v2.argotunnel.com
  nft add element inet transparent_proxy high_priority_transparent_proxy_v4 { 198.41.192.167, 198.41.192.67, 198.41.192.57, 198.41.192.107, 198.41.192.27, 198.41.192.7, 198.41.192.227, 198.41.192.47, 198.41.192.37, 198.41.192.77 }
  nft add element inet transparent_proxy high_priority_transparent_proxy_v6 { 2606:4700:a0::1, 2606:4700:a0::2, 2606:4700:a0::3, 2606:4700:a0::4, 2606:4700:a0::5, 2606:4700:a0::6, 2606:4700:a0::7, 2606:4700:a0::8, 2606:4700:a0::9, 2606:4700:a0::10 }

  # region2.v2.argotunnel.com
  nft add element inet transparent_proxy high_priority_transparent_proxy_v4 { 198.41.200.13, 198.41.200.193, 198.41.200.33, 198.41.200.233, 198.41.200.53, 198.41.200.63, 198.41.200.113, 198.41.200.73, 198.41.200.43, 198.41.200.23 }
  nft add element inet transparent_proxy high_priority_transparent_proxy_v6 { 2606:4700:a8::1, 2606:4700:a8::2, 2606:4700:a8::3, 2606:4700:a8::4, 2606:4700:a8::5, 2606:4700:a8::6, 2606:4700:a8::7, 2606:4700:a8::8, 2606:4700:a8::9, 2606:4700:a8::10 }

  nft add rule inet transparent_proxy prerouting mark 0xff counter return
  nft add rule inet transparent_proxy prerouting ip daddr @non_public_v4 counter return
  nft add rule inet transparent_proxy prerouting ip6 daddr @non_public_v6 counter return
  nft add rule inet transparent_proxy prerouting ip daddr @proxy_server_v4 counter return
  nft add rule inet transparent_proxy prerouting ip6 daddr @proxy_server_v6 counter return
  nft add rule inet transparent_proxy prerouting meta l4proto {tcp, udp} ip daddr @high_priority_transparent_proxy_v4 mark set 1 tproxy ip to :3348 counter accept
  nft add rule inet transparent_proxy prerouting meta l4proto {tcp, udp} ip6 daddr @high_priority_transparent_proxy_v6 mark set 1 tproxy ip6 to :3349 counter accept
  nft add rule inet transparent_proxy prerouting ip daddr @direct_v4 counter return
  nft add rule inet transparent_proxy prerouting ip6 daddr @direct_v6 counter return
  nft add rule inet transparent_proxy prerouting meta l4proto {tcp, udp} ip daddr 8.8.8.8/32 mark set 1 tproxy ip to :3346 counter accept
  nft add rule inet transparent_proxy prerouting meta l4proto {tcp, udp} ip daddr @transparent_proxy_v4 mark set 1 tproxy ip to :3346 counter accept
  nft add rule inet transparent_proxy prerouting meta l4proto {tcp, udp} ip6 daddr @transparent_proxy_v6 mark set 1 tproxy ip6 to :3347 counter accept
  nft add rule inet transparent_proxy prerouting counter return

  nft add chain inet transparent_proxy output { type route hook output priority 0 \; }
  nft add rule inet transparent_proxy output mark 0xff counter return
  nft add rule inet transparent_proxy output ip daddr @non_public_v4 counter return
  nft add rule inet transparent_proxy output ip6 daddr @non_public_v6 counter return
  nft add rule inet transparent_proxy output ip daddr @proxy_server_v4 counter return
  nft add rule inet transparent_proxy output ip6 daddr @proxy_server_v6 counter return
  nft add rule inet transparent_proxy output meta l4proto {tcp, udp} ip daddr @high_priority_transparent_proxy_v4 mark set 1 counter accept
  nft add rule inet transparent_proxy output meta l4proto {tcp, udp} ip6 daddr @high_priority_transparent_proxy_v6 mark set 1 counter accept
  nft add rule inet transparent_proxy output ip daddr @direct_v4 counter return
  nft add rule inet transparent_proxy output ip6 daddr @direct_v6 counter return
  nft add rule inet transparent_proxy output meta l4proto {tcp, udp} ip daddr 8.8.8.8/32 mark set 1 counter accept
  nft add rule inet transparent_proxy output meta l4proto {tcp, udp} ip daddr @transparent_proxy_v4 mark set 1 counter accept
  nft add rule inet transparent_proxy output meta l4proto {tcp, udp} ip6 daddr @transparent_proxy_v6 mark set 1 counter accept
  nft add rule inet transparent_proxy output counter return

  nft add table inet filter
  nft add chain inet filter divert { type filter hook prerouting priority -150 \; }
  nft add rule inet filter divert meta l4proto tcp socket transparent 1 meta mark set 1 accept
}

stop() {
  ip route del local default dev lo table 100
  ip rule del table 100
  ip -f inet6 rule del fwmark 1 table 100
  ip -6 route del local ::/0 dev lo table 100
  nft flush table inet transparent_proxy
  nft flush table inet filter
  nft delete set inet transparent_proxy direct_v4
  nft delete set inet transparent_proxy direct_v6
  nft delete set inet transparent_proxy non_public_v4
  nft delete set inet transparent_proxy non_public_v6
  nft delete set inet transparent_proxy proxy_server_v4
  nft delete set inet transparent_proxy proxy_server_v6
}
```

##### create_nft_set
``` 
#!/bin/sh /etc/rc.common
# "new(er)" style init script
# Look at /lib/functions/service.sh on a running system for explanations of what other SERVICE_
# options you can use, and when you might want them.

START=20

start() {
  nft add table inet transparent_proxy
  nft add chain inet transparent_proxy prerouting { type filter hook prerouting priority -50 \; }
  nft add set inet transparent_proxy transparent_proxy_v4 { type ipv4_addr\; flags interval\; }
  nft add set inet transparent_proxy transparent_proxy_v6 { type ipv6_addr\; flags interval\; }
  nft add set inet transparent_proxy high_priority_transparent_proxy_v4 { type ipv4_addr\; flags interval\; }
  nft add set inet transparent_proxy high_priority_transparent_proxy_v6 { type ipv6_addr\; flags interval\; }
}

stop() {}
```


#### sing-box 配置
```
{
    "log": {
        "disabled": true,
        "level": "debug",
        "timestamp": true
    },
    "dns": {
        "servers": [
            {
                "tag": "dns-backend",
                "address": "10.0.0.1:5354",
                "strategy": "prefer_ipv4",
                "detour": "out-bound-direct"
            },
            {
                "tag": "dns-cloudflare",
                "address": "https://1.1.1.1/dns-query",
                "strategy": "prefer_ipv4",
                "detour": "out-bound-hk"
            },
            {
                "tag": "dns-refused",
                "address": "rcode://name_error"
            }
        ],
        "rules": [
            {
                "rule_set": [
                    "geosite-microsoft"
                ],
                "server": "dns-backend",
                "disable_cache": true
            },
            {
                "rule_set": [
                    "geosite-steam-cn"
                ],
                "server": "dns-backend",
                "disable_cache": true
            },
            {
                "rule_set": [
                    "geosite-ads"
                ],
                "server": "dns-refused"
            },
            {
                "rule_set": [
                    "geosite-steam"
                ],
                "server": "dns-cloudflare"
            },
            {
                "rule_set": [
                    "geoip-cn",
                    "geosite-cn",
                    "geosite-china-list"
                ],
                "server": "dns-backend",
                "disable_cache": true
            }
        ],
        "final": "dns-cloudflare",
        "strategy": "prefer_ipv4",
        "disable_cache": true,
        "disable_expire": false,
        "independent_cache": false,
        "reverse_mapping": false
    },
    "ntp": {
        "enabled": true,
        "server": "10.0.0.1",
        "server_port": 123,
        "interval": "30m"
    },
    "inbounds": [
        {
            "type": "socks",
            "listen": "0.0.0.0",
            "listen_port": 1080,
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "50ms",
            "domain_strategy": "prefer_ipv4",
            "udp_disable_domain_unmapping": true,
            "tcp_fast_open": true,
            "tcp_multi_path": true,
            "udp_fragment": true
        },
        {
            "type": "http",
            "listen": "0.0.0.0",
            "listen_port": 8080,
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "50ms",
            "domain_strategy": "prefer_ipv4",
            "udp_disable_domain_unmapping": true,
            "tcp_fast_open": true,
            "tcp_multi_path": true,
            "udp_fragment": true
        },
        {
            "type": "tproxy",
            "tag": "inbound-tproxy-ipv4",
            "listen": "0.0.0.0",
            "listen_port": 3346,
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "50ms",
            "udp_disable_domain_unmapping": true,
            "tcp_fast_open": true,
            "tcp_multi_path": true,
            "udp_fragment": true
        },
        {
            "type": "tproxy",
            "tag": "inbound-tproxy-ipv6",
            "listen": "::",
            "listen_port": 3347,
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "50ms",
            "udp_disable_domain_unmapping": true,
            "tcp_fast_open": true,
            "tcp_multi_path": true,
            "udp_fragment": true
        },
        {
            "type": "tproxy",
            "tag": "inbound-tproxy-ipv4-no-sniff",
            "listen": "0.0.0.0",
            "listen_port": 3348,
            "sniff": false,
            "sniff_override_destination": false,
            "udp_disable_domain_unmapping": true,
            "tcp_fast_open": true,
            "tcp_multi_path": true,
            "udp_fragment": true
        },
        {
            "type": "tproxy",
            "tag": "inbound-tproxy-ipv6-no-sniff",
            "listen": "::",
            "listen_port": 3349,
            "sniff": false,
            "sniff_override_destination": false,
            "udp_disable_domain_unmapping": true,
            "tcp_fast_open": true,
            "tcp_multi_path": true,
            "udp_fragment": true
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "out-bound-direct",
            "routing_mark": 255
        },
        {
            "type": "block",
            "tag": "out-bound-block"
        },
        {
            "type": "dns",
            "tag": "out-bound-dns"
        },
        {
            "tag": "out-bound-hk",
        },
        {
            "tag": "out-bound-en",
        },
        {
            "type": "selector",
            "tag": "out-bound-common-balanced",
            "outbounds": [
                "out-bound-hk",
                "out-bound-en"
            ],
            "default": "out-bound-hk",
            "interrupt_exist_connections": false
        }
    ],
    "route": {
        "rules": [
            {
                "ip_is_private": true,
                "outbound": "out-bound-direct"
            },
            {
                "rule_set": [
                    "geoip-private"
                ],
                "outbound": "out-bound-direct"
            },
            {
                "ip_cidr": [
                    "10.0.0.0/16"
                ],
                "outbound": "out-bound-direct"
            },
            {
                "ip_cidr": [
                    "8.8.8.8"
                ],
                "outbound": "out-bound-hk"
            },
            {
                "ip_cidr": [
                    代理服务器
                ],
                "outbound": "out-bound-direct"
            },
            {
                "protocol": "dns",
                "outbound": "out-bound-dns"
            },
            {
                "protocol": "bittorrent",
                "outbound": "out-bound-direct"
            },
            {
                "domain_suffix": [
                    "v2.argotunnel.com",
                    "cftunnel.com",
                    "h2.cftunnel.com",
                    "quic.cftunnel.com"
                ],
                "outbound": "out-bound-hk"
            },
            {
                "rule_set": [
                    "geosite-ads",
                    "geoip-ads"
                ],
                "outbound": "out-bound-block"
            },
            {
                "rule_set": [
                    "geosite-steam-cn"
                ],
                "outbound": "out-bound-direct"
            },
            {
                "rule_set": [
                    "geosite-steam"
                ],
                "outbound": "out-bound-hk"
            },
            {
                "domain_suffix": [
                    "oaistatic.com",
                    "openai.com",
                    "chatgpt.com"
                ],
                "outbound": "out-bound-en"
            },
            {
                "rule_set": [
                    "geosite-openai"
                ],
                "outbound": "out-bound-en"
            },
            {
                "rule_set": [
                    "geosite-netflix",
                    "geoip-netflix"
                ],
                "outbound": "out-bound-en"
            },
            {
                "rule_set": [
                    "geosite-youtube"
                ],
                "outbound": "out-bound-en"
            },
            {
                "rule_set": [
                    "geoip-cn",
                    "geosite-cn",
                    "geosite-china-list"
                ],
                "outbound": "out-bound-direct"
            },
            {
                "ip_cidr": [
                    "::/0"
                ],
                "outbound": "out-bound-en"
            }
        ],
        "rule_set": [
            {
                "tag": "geoip-private",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/private.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/cn.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-cn.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-china-list",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-china-list.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-google",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-google.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geoip-google",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/google.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geoip-ads",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/ad.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-ads",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-category-ads-all.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-netflix.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geoip-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/netflix.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-openai",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-openai.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-youtube",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-youtube.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-steam",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-steam.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-steam-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-steam@cn.srs",
                "download_detour": "out-bound-hk"
            },
            {
                "tag": "geosite-microsoft",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-microsoft.srs",
                "download_detour": "out-bound-hk"
            }
        ],
        "final": "out-bound-hk"
    }
}
```