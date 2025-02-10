### Installation

- brew install libpcap pcre
- brew install snort
- snort -V

### Configure SNORT

- mkdir -p /usr/local/etc/snort/rules
- vi /usr/local/etc/snort/snort.lua
    - Set HOME_NET: "[your-network]"
    - Set EXTERNAL_NET: "!$HOME_NET"

- touch /usr/local/etc/snort/rules/local.rules
- vi local.rules and add custom rules:-
    <pre>
        alert icmp any any -> any any (msg:"ICMP Echo Request detected"; itype:8; sid:1000001; rev:1;)
        alert icmp any any -> any any (msg:"ICMP Echo Reply detected"; itype:0; sid:1000002; rev:1;)
        alert tcp any any -> any any (msg:"Nmap Stealth Scan Detected"; flags:S; detection_filter: track by_src, count 5, seconds 10; sid:100003;)
    </pre>


### Start Snort

- snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/snort/rules/local.rules --lua 'ips = { enable_builtin_rules = true }' -A alert_fast -q -i en0

### Observe Logs

<pre>

1. ICMP Alerts

ping -c3 example.com

02/10-15:35:37.381248 [**] [1:1000001:1] "ICMP Echo Request detected" [**] [Priority: 0] {ICMP} 192.168.29.79 -> 23.215.0.138
02/10-15:35:37.794000 [**] [1:1000002:1] "ICMP Echo Reply detected" [**] [Priority: 0] {ICMP} 23.215.0.138 -> 192.168.29.79
02/10-15:35:37.795740 [**] [116:444:1] "(ipv4) IPv4 option set" [**] [Priority: 3] {IP} 192.168.29.1 -> 224.0.0.1
02/10-15:35:38.386556 [**] [1:1000001:1] "ICMP Echo Request detected" [**] [Priority: 0] {ICMP} 192.168.29.79 -> 23.215.0.138
02/10-15:35:38.736098 [**] [1:1000002:1] "ICMP Echo Reply detected" [**] [Priority: 0] {ICMP} 23.215.0.138 -> 192.168.29.79
02/10-15:35:39.391759 [**] [1:1000001:1] "ICMP Echo Request detected" [**] [Priority: 0] {ICMP} 192.168.29.79 -> 23.215.0.138
02/10-15:35:39.842521 [**] [1:1000002:1] "ICMP Echo Reply detected" [**] [Priority: 0] {ICMP} 23.215.0.138 -> 192.168.29.79

</pre>

<pre>
NMAP Stealth Scan Alerts

sudo nmap -Pn -sS -p- 192.168.79.29

02/10-15:36:25.996389 [**] [1:100003:0] "Nmap Stealth Scan Detected" [**] [Priority: 0] {TCP} 192.168.29.79:53925 -> 192.168.79.29:80
02/10-15:36:25.996402 [**] [1:100003:0] "Nmap Stealth Scan Detected" [**] [Priority: 0] {TCP} 192.168.29.79:53925 -> 192.168.79.29:8080
02/10-15:36:25.996417 [**] [1:100003:0] "Nmap Stealth Scan Detected" [**] [Priority: 0] {TCP} 192.168.29.79:53925 -> 192.168.79.29:21
02/10-15:36:25.996429 [**] [1:100003:0] "Nmap Stealth Scan Detected" [**] [Priority: 0] {TCP} 192.168.29.79:53925 -> 192.168.79.29:3306
02/10-15:36:25.996445 [**] [1:100003:0] "Nmap Stealth Scan Detected" [**] [Priority: 0] {TCP} 192.168.29.79:53925 -> 192.168.79.29:256
...
...
...
</pre>
