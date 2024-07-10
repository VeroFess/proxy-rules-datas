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

```
root@KernelRouter:~# cat /etc/init.d/tproxy
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

  nft add set inet proxy specialv4 { type ipv4_addr\; flags constant, interval\; }
  nft add set inet proxy specialv6 { type ipv6_addr\; flags constant, interval\; }
  nft add set inet proxy proxysrvv4 { type ipv4_addr\; flags constant\; }
  nft add set inet proxy proxysrvv6 { type ipv6_addr\; flags constant\; }

  nft add element inet proxy specialv4 { 10.0.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 224.0.0.0/4, 240.0.0.0/4 }
  nft add element inet proxy specialv6 { ::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001::/23, 2001:db8::/32, 2002::/16, 2620:4f:8000::/48, fc00::/7, fe80::/10 }

  nft add element inet proxy proxysrvv4 { 代理服务器的地址(们) }
  nft add element inet proxy proxysrvv6 { 代理服务器的地址(们) }

  # telegram 的 ip 段, https://core.telegram.org/resources/cidr.txt
  nft add element inet proxy gfwv4 { 91.108.56.0/22, 91.108.4.0/22, 91.108.8.0/22, 91.108.16.0/22, 91.108.12.0/22, 149.154.160.0/20, 91.105.192.0/23, 91.108.20.0/22, 185.76.151.0/24 }
  nft add element inet proxy gfwv6 { 2001:b28:f23d::/48, 2001:b28:f23f::/48, 2001:67c:4e8::/48, 2001:b28:f23c::/48, 2a0a:f280::/32 }

  # cloudflare warp
  nft add element inet proxy gfwv4 { 162.159.192.0/24, 162.159.193.0/24, 162.159.197.0/24 }
  nft add element inet proxy gfwv6 { 2606:4700:100::/48, 2606:4700:102::/48 }

  nft add rule inet proxy prerouting ip daddr @specialv4 return
  nft add rule inet proxy prerouting ip6 daddr @specialv6 return
  nft add rule inet proxy prerouting ip daddr @proxysrvv4 return
  nft add rule inet proxy prerouting ip6 daddr @proxysrvv6 return
  nft add rule inet proxy prerouting ip daddr @chnv4 return
  nft add rule inet proxy prerouting ip6 daddr @chnv6 return
  nft add rule inet proxy prerouting mark 0xff return
  nft add rule inet proxy prerouting meta l4proto {tcp, udp} ip daddr 8.8.8.8/32 mark set 1 tproxy ip to :3346 accept
  nft add rule inet proxy prerouting meta l4proto {tcp, udp} ip daddr @gfwv4 mark set 1 tproxy ip to :3346 accept
  nft add rule inet proxy prerouting meta l4proto {tcp, udp} ip6 daddr @gfwv6 mark set 1 tproxy ip6 to :3347 accept
  nft add rule inet proxy prerouting return

  nft add chain inet proxy output { type route hook output priority 0 \; }
  nft add rule inet proxy output ip daddr @specialv4 return
  nft add rule inet proxy output ip6 daddr @specialv6 return
  nft add rule inet proxy output ip daddr @proxysrvv4 return
  nft add rule inet proxy output ip6 daddr @proxysrvv6 return
  nft add rule inet proxy output ip daddr @chnv4 return
  nft add rule inet proxy output ip6 daddr @chnv6 return
  nft add rule inet proxy output mark 0xff return
  nft add rule inet proxy output meta l4proto {tcp, udp} ip daddr @gfwv4 mark set 1 accept
  nft add rule inet proxy output meta l4proto {tcp, udp} ip6 daddr @gfwv6 mark set 1 accept
  nft add rule inet proxy output return

  nft add table inet filter
  nft add chain inet filter divert { type filter hook prerouting priority -150 \; }
  nft add rule inet filter divert meta l4proto tcp socket transparent 1 meta mark set 1 accept
}

stop() {
  ip route del local default dev lo table 100
  ip rule del table 100
  ip -f inet6 rule del fwmark 1 table 100
  ip -6 route del local ::/0 dev lo table 100
  nft flush table inet proxy
  nft flush table inet filter
  nft delete set inet proxy chnv4
  nft delete set inet proxy chnv6
  nft delete set inet proxy specialv4
  nft delete set inet proxy specialv6
  nft delete set inet proxy proxysrvv4
  nft delete set inet proxy proxysrvv6
}
```

### sing-box 配置

```
{
    "log": {
        "disabled": false,
        "level": "debug",
        "timestamp": false
    },
    "dns": {
        "servers": [
            {
                "tag": "dns-adguardhome",
                "address": "10.0.0.1:5353",
                "strategy": "prefer_ipv4",
                "detour": "out-bound-direct"
            },
            {
                "tag": "dns-cloudflare",
                "address": "https://1.1.1.1/dns-query",
                "strategy": "prefer_ipv4",
                "detour": "proxy-hk"
            },
            {
                "tag": "dns-refused",
                "address": "rcode://name_error"
            }
        ],
        "rules": [
            {
                "rule_set": [
                    "geosite-steam-cn"
                ],
                "server": "dns-adguardhome",
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
                "server": "dns-adguardhome",
                "disable_cache": true
            }
        ],
        "final": "dns-cloudflare",
        "strategy": "prefer_ipv4",
        "disable_cache": false,
        "disable_expire": false,
        "independent_cache": true,
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
            "type": "mixed",
            "listen": "0.0.0.0",
            "listen_port": 1080,
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "300ms",
            "domain_strategy": "prefer_ipv4",
            "udp_disable_domain_unmapping": true
        },
        {
            "type": "mixed",
            "listen": "0.0.0.0",
            "listen_port": 8080,
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "300ms",
            "domain_strategy": "prefer_ipv4",
            "udp_disable_domain_unmapping": true
        },
        {
            "type": "tproxy",
            "tag": "inbound-tproxy-ipv4",
            "listen": "0.0.0.0",
            "listen_port": 3346,
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "300ms",
            "udp_disable_domain_unmapping": true
        },
        {
            "type": "tproxy",
            "tag": "inbound-tproxy-ipv6",
            "listen": "::",
            "listen_port": 3347,
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "300ms",
            "udp_disable_domain_unmapping": true
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "out-bound-direct"
        },
        {
            "type": "block",
            "tag": "out-bound-block"
        },
        {
            "tag": "proxy-hk"
        },
        {
            "tag": "proxy-en"
        },
        {
            "type": "selector",
            "tag": "out-bound-balanced",
            "outbounds": [
                "proxy-hk",
                "proxy-en"
            ],
            "default": "proxy-hk",
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
                    "代理服务器",
                    "代理服务器"
                ],
                "outbound": "out-bound-direct"
            },
            {
                "ip_cidr": [
                    "8.8.8.8"
                ],
                "outbound": "proxy-hk"
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
                "outbound": "proxy-hk"
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
                "outbound": "proxy-en"
            },
            {
                "domain_suffix": [
                    "oaistatic.com",
                    "openai.com",
                    "chatgpt.com"
                ],
                "outbound": "proxy-en"
            },
            {
                "rule_set": [
                    "geosite-openai"
                ],
                "outbound": "proxy-en"
            },
            {
                "rule_set": [
                    "geosite-netflix",
                    "geoip-netflix"
                ],
                "outbound": "proxy-en"
            },
            {
                "rule_set": [
                    "geosite-youtube"
                ],
                "outbound": "proxy-en"
            }
        ],
        "rule_set": [
            {
                "tag": "geoip-private",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/private.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/cn.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-cn.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geosite-china-list",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-china-list.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geosite-google",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-google.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geoip-google",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/google.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geoip-ads",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/ad.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geosite-ads",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-category-ads-all.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geosite-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-netflix.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geoip-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geoip-srs/netflix.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geosite-openai",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-openai.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geosite-youtube",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-youtube.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geosite-steam",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-steam.srs",
                "download_detour": "proxy-hk"
            },
            {
                "tag": "geosite-steam-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/VeroFess/proxy-rules-datas/data/geosite-srs/geosite-steam@cn.srs",
                "download_detour": "proxy-hk"
            }
        ],
        "final": "out-bound-balanced"
    }
}
```
