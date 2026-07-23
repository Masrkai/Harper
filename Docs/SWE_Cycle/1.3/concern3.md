[INFO ] Poisoning active. Press Ctrl-C or 'q' + Enter to stop and restore.
[*] SpooferEngine started
    Gateway IP:  192.168.1.1
    Our MAC:     62:fe:1e:0a:36:19
    Interface:   wlan0
[*] Starting ARP poison for host 2:
    Victim:  192.168.1.4 @ 42:fa:fe:44:12:98
    Gateway: 192.168.1.1 @ 58:ba:d4:8e:37:2a
[+] Poison loop started for host 2 (dedicated socket)
[*] Starting ARP poison for host 3:
    Victim:  192.168.1.5 @ 2a:a0:bc:b7:e2:00
    Gateway: 192.168.1.1 @ 58:ba:d4:8e:37:2a
[+] Poison loop started for host 3 (dedicated socket)
[*] poison gateway #3 for host 192.168.1.4 (every ~30s)
[*] poison gateway #3 for host 192.168.1.5 (every ~30s)
[*] poison victim #5 host 192.168.1.5 (every ~25s)
[*] poison victim #5 host 192.168.1.4 (every ~25s)
[*] poison gateway #6 for host 192.168.1.4 (every ~30s)
[*] poison gateway #6 for host 192.168.1.5 (every ~30s)
[*] poison victim #10 host 192.168.1.5 (every ~25s)
[*] poison gateway #9 for host 192.168.1.4 (every ~30s)
[*] poison victim #10 host 192.168.1.4 (every ~25s)
[*] poison gateway #9 for host 192.168.1.5 (every ~30s)
[*] garp self #3 for 192.168.1.27 (every ~120s)
[*] garp self #3 for 192.168.1.27 (every ~120s)
[*] Stopping poison for host 2…
[*] stopping poison for host 2
[*] restoring ARP caches for 192.168.1.4
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 1 victim(s) share a pool (upload: Some(10), download: Some(600)).
[*] Auto-MITM: evicted stale victim [2]
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 1 victim(s) share a pool (upload: Some(10), download: Some(600)).
[+] Auto-MITM: added victim [4] 192.168.1.4 (42:fa:fe:44:12:98)
[+] ARP caches restored for 192.168.1.4
[+] Poison stopped cleanly for host 2
[*] Starting ARP poison for host 4:
    Victim:  192.168.1.4 @ 42:fa:fe:44:12:98
    Gateway: 192.168.1.1 @ 58:ba:d4:8e:37:2a
[+] Poison loop started for host 4 (dedicated socket)
[*] Starting ARP poison for host 5:
    Victim:  192.168.1.28 @ fa:75:7c:85:db:10
    Gateway: 192.168.1.1 @ 58:ba:d4:8e:37:2a
[+] Poison loop started for host 5 (dedicated socket)
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 2 victim(s) share a pool (upload: Some(10), download: Some(600)).
[+] Auto-MITM: added victim [5] 192.168.1.28 (fa:75:7c:85:db:10)
[*] poison victim #15 host 192.168.1.5 (every ~25s)
[*] poison gateway #12 for host 192.168.1.5 (every ~30s)
[*] poison gateway #3 for host 192.168.1.4 (every ~30s)
[*] poison gateway #3 for host 192.168.1.28 (every ~30s)
[*] poison victim #5 host 192.168.1.4 (every ~25s)
[*] poison victim #5 host 192.168.1.28 (every ~25s)
[*] poison gateway #15 for host 192.168.1.5 (every ~30s)
[*] poison victim #20 host 192.168.1.5 (every ~25s)
[*] poison gateway #6 for host 192.168.1.4 (every ~30s)
[*] poison gateway #6 for host 192.168.1.28 (every ~30s)
[*] poison gateway #18 for host 192.168.1.5 (every ~30s)
[*] poison victim #10 host 192.168.1.4 (every ~25s)
[*] garp self #3 for 192.168.1.27 (every ~120s)
[*] poison victim #10 host 192.168.1.28 (every ~25s)
[*] poison gateway #9 for host 192.168.1.4 (every ~30s)
[*] garp self #3 for 192.168.1.27 (every ~120s)
[*] poison gateway #9 for host 192.168.1.28 (every ~30s)
[*] poison victim #25 host 192.168.1.5 (every ~25s)
[*] garp self #6 for 192.168.1.27 (every ~120s)
[*] poison gateway #21 for host 192.168.1.5 (every ~30s)
[*] poison gateway #12 for host 192.168.1.4 (every ~30s)
[*] Stopping poison for host 4…
[*] stopping poison for host 4
[*] restoring ARP caches for 192.168.1.4
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 2 victim(s) share a pool (upload: Some(10), download: Some(600)).
[*] Auto-MITM: evicted stale victim [4]
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 2 victim(s) share a pool (upload: Some(10), download: Some(600)).
[+] Auto-MITM: added victim [6] 192.168.1.4 (42:fa:fe:44:12:98)
[+] ARP caches restored for 192.168.1.4
[+] Poison stopped cleanly for host 4
[*] Starting ARP poison for host 6:
    Victim:  192.168.1.4 @ 42:fa:fe:44:12:98
    Gateway: 192.168.1.1 @ 58:ba:d4:8e:37:2a
[+] Poison loop started for host 6 (dedicated socket)
[*] poison gateway #12 for host 192.168.1.28 (every ~30s)
[*] poison victim #15 host 192.168.1.28 (every ~25s)
[*] poison gateway #3 for host 192.168.1.4 (every ~30s)
[*] poison victim #30 host 192.168.1.5 (every ~25s)
[*] poison gateway #24 for host 192.168.1.5 (every ~30s)
[*] poison victim #5 host 192.168.1.4 (every ~25s)
[*] poison gateway #15 for host 192.168.1.28 (every ~30s)
[*] poison gateway #6 for host 192.168.1.4 (every ~30s)
[*] poison gateway #27 for host 192.168.1.5 (every ~30s)
[*] poison victim #20 host 192.168.1.28 (every ~25s)
[*] poison victim #35 host 192.168.1.5 (every ~25s)
[*] poison gateway #18 for host 192.168.1.28 (every ~30s)
[*] garp self #3 for 192.168.1.27 (every ~120s)
[*] poison victim #10 host 192.168.1.4 (every ~25s)
[*] poison gateway #9 for host 192.168.1.4 (every ~30s)
[*] poison gateway #30 for host 192.168.1.5 (every ~30s)
[*] garp self #9 for 192.168.1.27 (every ~120s)
[*] poison victim #25 host 192.168.1.28 (every ~25s)
[*] poison gateway #21 for host 192.168.1.28 (every ~30s)
[*] poison victim #40 host 192.168.1.5 (every ~25s)
[*] garp self #6 for 192.168.1.27 (every ~120s)
[*] poison gateway #33 for host 192.168.1.5 (every ~30s)
[*] Stopping poison for host 5…
[*] stopping poison for host 5
[*] restoring ARP caches for 192.168.1.28
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 2 victim(s) share a pool (upload: Some(10), download: Some(600)).
[*] Auto-MITM: evicted stale victim [5]
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 1 victim(s) share a pool (upload: Some(10), download: Some(600)).
[*] Auto-MITM: evicted stale victim [6]
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 1 victim(s) share a pool (upload: Some(10), download: Some(600)).
[+] Auto-MITM: added victim [7] 192.168.1.28 (fa:75:7c:85:db:10)
[+] ARP caches restored for 192.168.1.28
[+] Poison stopped cleanly for host 5
[*] Stopping poison for host 6…
[*] stopping poison for host 6
[*] restoring ARP caches for 192.168.1.4
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 2 victim(s) share a pool (upload: Some(10), download: Some(600)).
[+] Auto-MITM: added victim [8] 192.168.1.4 (42:fa:fe:44:12:98)
[+] ARP caches restored for 192.168.1.4
[+] Poison stopped cleanly for host 6
[*] Starting ARP poison for host 7:
    Victim:  192.168.1.28 @ fa:75:7c:85:db:10
    Gateway: 192.168.1.1 @ 58:ba:d4:8e:37:2a
[+] Poison loop started for host 7 (dedicated socket)
[*] Starting ARP poison for host 8:
    Victim:  192.168.1.4 @ 42:fa:fe:44:12:98
    Gateway: 192.168.1.1 @ 58:ba:d4:8e:37:2a
[+] Poison loop started for host 8 (dedicated socket)
[*] poison gateway #3 for host 192.168.1.4 (every ~30s)
[*] poison gateway #3 for host 192.168.1.28 (every ~30s)
[*] poison victim #5 host 192.168.1.28 (every ~25s)
[*] poison gateway #36 for host 192.168.1.5 (every ~30s)
[*] poison victim #45 host 192.168.1.5 (every ~25s)
[*] poison victim #5 host 192.168.1.4 (every ~25s)

Broadcast message from root@NixOS (somewhere) (Thu Jul 23 08:57:04 2026):

Problem detected with disk: /dev/sda [USB NVMe Realtek]
Warning message from smartd is:

Device: /dev/sda [USB NVMe Realtek], unable to open NVMe device

[*] poison gateway #6 for host 192.168.1.28 (every ~30s)
[*] poison gateway #6 for host 192.168.1.4 (every ~30s)
[*] poison gateway #39 for host 192.168.1.5 (every ~30s)
[*] Starting ARP poison for host 9:
    Victim:  192.168.1.12 @ 58:a6:39:4a:5d:43
    Gateway: 192.168.1.1 @ 58:ba:d4:8e:37:2a
[+] Poison loop started for host 9 (dedicated socket)
[*] tc: warning: failed to remove class 1:ffe: Error: HTB class in use.
[*] tc: warning: failed to remove class 2:ffe: Error: HTB class in use.
[+] tc: 3 victim(s) share a pool (upload: Some(10), download: Some(600)).
[+] Auto-MITM: added victim [9] 192.168.1.12 (58:a6:39:4a:5d:43)
[*] garp self #3 for 192.168.1.27 (every ~120s)
[*] poison victim #10 host 192.168.1.28 (every ~25s)
[*] poison victim #50 host 192.168.1.5 (every ~25s)
[*] poison gateway #9 for host 192.168.1.28 (every ~30s)
[*] poison victim #10 host 192.168.1.4 (every ~25s)
[*] garp self #3 for 192.168.1.27 (every ~120s)
[*] poison gateway #9 for host 192.168.1.4 (every ~30s)
[*] poison gateway #3 for host 192.168.1.12 (every ~30s)
[*] poison gateway #42 for host 192.168.1.5 (every ~30s)
[*] poison victim #5 host 192.168.1.12 (every ~25s)
[*] garp self #12 for 192.168.1.27 (every ~120s)
