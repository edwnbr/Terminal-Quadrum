#!/usr/bin/env python3
import random
import time
import threading
import sys

running_loops = True

# ------------------------------------
# base print helpers
# ------------------------------------

def slow(text, delay=0.003):
    for c in text:
        print(c, end="", flush=True)
        time.sleep(delay)
    print()

def line():
    print("-" * 55)

def rand_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def rand_hex(size=8):
    return hex(random.randint(0, 16**size))[2:].zfill(size)

# ------------------------------------
# SYSTEM MODULES
# ------------------------------------

def sysinfo():
    line()
    slow("System Overview:")
    slow(f"Kernel:     linux-{random.randint(4,6)}.{random.randint(0,19)}.{random.randint(0,255)}")
    slow(f"CPU Cores:  {random.choice([2,4,8,16,32])}")
    slow(f"RAM:        {random.choice([4,8,16,32,64,128])} GB")
    slow(f"Uptime:     {random.randint(1,999)}h")
    line()

def syscheck():
    slow("[system] integrity check...")
    for _ in range(6):
        slow(f"[chk] module {rand_hex(4)} → OK")

def sysmon():
    for _ in range(12):
        slow(f"[sysmon] cpu={random.randint(1,99)}% mem={random.randint(1,99)}% io={random.randint(1,99)}%")

def memmap():
    slow("Memory map segments:")
    for _ in range(10):
        slow(f"SEG 0x{rand_hex(6)} → size={random.randint(1,64)}MB")

def cpu_heat():
    slow("Thermal status:")
    for _ in range(6):
        slow(f"core{random.randint(0,15)} → {random.randint(30,89)}°C")

def kern_events():
    for _ in range(12):
        slow(f"[kern] evt@0x{rand_hex(6)} type={random.choice(['IRQ','WARN','TRACE'])}")

# ------------------------------------
# NETWORK MODULES
# ------------------------------------

def netmap():
    slow("Active network routes:")
    for _ in range(7):
        slow(f"{rand_ip()} → {rand_ip()} via eth0")

def netstat():
    for _ in range(12):
        slow(f"[net] {rand_ip()}:{random.randint(20,65000)} STATE={random.choice(['EST','SYN','ACK','TIME_WAIT'])}")

def netprobe():
    for _ in range(6):
        slow(f"[probe] scanning {rand_ip()} → {random.choice(['open','closed','filtered'])}")

def route_scan():
    slow("Route propagation logs:")
    for _ in range(8):
        slow(f"route-id {rand_hex(4)} update {rand_ip()} latency {random.randint(1,200)}ms")

def dns_lookup():
    slow("DNS resolution trace:")
    for _ in range(6):
        slow(f"lookup {rand_hex(6)}.net → {rand_ip()}")

def arp_enum():
    slow("ARP Table:")
    for _ in range(8):
        slow(f"{rand_ip()}  aa:{rand_hex(2)}:{rand_hex(2)}:{rand_hex(2)}:ff")

# ------------------------------------
# SECURITY MODULES
# ------------------------------------

def vulnscan():
    slow("Vulnerability scan:")
    for _ in range(10):
        slow(f"[vuln] CVE-{random.randint(2016,2025)}-{rand_hex(4)} → {random.choice(['safe','exposed','patch-required'])}")

def portscan():
    slow("Port scan:")
    for port in random.sample(range(20,9999), 15):
        slow(f"port {port} → {random.choice(['open','closed','filtered'])}")

def breach_attempt():
    slow("[breach] escalating privileges…")
    for _ in range(5):
        slow(f"[brc] step={rand_hex(3)} result={random.choice(['OK','FAIL'])}")

def proto_fuzz():
    slow("Protocol fuzzing:")
    for _ in range(12):
        slow(f"[fuzz] proto={random.choice(['http','ssh','tls','icmp'])} code={rand_hex(3)}")

def firewall_trace():
    for _ in range(8):
        slow(f"[fw] DROP {rand_ip()}:{random.randint(20,9999)}")

def threat_feed():
    slow("Threat-feed updates:")
    for _ in range(8):
        slow(f"[feed] IOC {rand_hex(12)} risk={random.randint(1,10)}")

# ------------------------------------
# CLOUD MODULES
# ------------------------------------

def s3_enum():
    slow("Cloud storage enumeration:")
    for _ in range(6):
        slow(f"bucket-{rand_hex(4)} → objects={random.randint(1,9999)}")

def cloud_auth():
    slow("Cloud auth logs:")
    for _ in range(8):
        slow(f"auth attempt {rand_hex(8)} → {random.choice(['OK','DENY'])}")

def instance_map():
    slow("Cloud instances:")
    for _ in range(6):
        slow(f"inst-{rand_hex(4)} → {rand_ip()} status={random.choice(['RUNNING','STOPPED','PENDING'])}")

def cloud_events():
    for _ in range(10):
        slow(f"[cloud] evt {rand_hex(6)} type={random.choice(['ALERT','CONFIG','IAM','NET'])}")

# ------------------------------------
# FILESYSTEM
# ------------------------------------

def fs_tree():
    slow("Filesystem tree:")
    for _ in range(12):
        slow(f"/var/log/{rand_hex(4)}")

def fs_search():
    slow("Searching filesystem:")
    for _ in range(10):
        slow(f"found file: /etc/{rand_hex(4)}.conf")

def shadow_files():
    slow("Shadow entries:")
    for _ in range(6):
        slow(f"user-{rand_hex(3)}:$1${rand_hex(8)}$")

def mount_enum():
    for _ in range(6):
        slow(f"/dev/{rand_hex(3)} mounted on /mnt/{rand_hex(2)}")

# ------------------------------------
# CRYPTO
# ------------------------------------

def hash_crack():
    slow("Hash cracking attempt:")
    for _ in range(8):
        slow(f"hash {rand_hex(32)} → {random.choice(['unresolved','match-found'])}")

def rsa_probe():
    slow("RSA key probe:")
    for _ in range(5):
        slow(f"modulus={rand_hex(64)}")

def key_enum():
    slow("Enumerating crypto keys:")
    for _ in range(6):
        slow(f"key-{rand_hex(4)} → bits={random.choice([256,512,1024,2048,4096])}")

def entropy_check():
    slow("Entropy levels:")
    for _ in range(8):
        slow(f"entropy={random.randint(1000,4096)}")

# ------------------------------------
# AI
# ------------------------------------

def ai_inspect():
    for _ in range(10):
        slow(f"[ai] node-{rand_hex(4)} state={random.choice(['active','idle','computed'])}")

def ai_trace():
    for _ in range(10):
        slow(f"[ai-trace] weight={rand_hex(6)} delta={random.randint(-5,5)}")

def ai_memory():
    for _ in range(8):
        slow(f"[ai-mem] block {rand_hex(5)} → {random.randint(1,100)}MB")

# ------------------------------------
# KERNEL
# ------------------------------------

def kern_dump():
    slow("Kernel dump:")
    for _ in range(15):
        slow(f"[dump] 0x{rand_hex(10)}")

def kern_trace():
    for _ in range(12):
        slow(f"[ktrace] syscall@{rand_hex(6)} latency={random.randint(1,999)}µs")

def syscall_map():
    for _ in range(10):
        slow(f"syscall {rand_hex(3)} → addr 0x{rand_hex(6)}")

# ------------------------------------
# OPS / DARKNET
# ------------------------------------

def onion_scan():
    for _ in range(6):
        slow(f"[onion] srv-{rand_hex(8)} → latency {random.randint(50,700)}ms")

def relay_trace():
    for _ in range(8):
        slow(f"[relay] hop={rand_hex(4)} {rand_ip()}")

def darknet_pulse():
    for _ in range(6):
        slow(f"[pulse] sig={rand_hex(12)}")

# ------------------------------------
# MASTER LOOP
# ------------------------------------

modules_list = [
    sysinfo, syscheck, sysmon, memmap, cpu_heat, kern_events,
    netmap, netstat, netprobe, route_scan, dns_lookup, arp_enum,
    vulnscan, portscan, breach_attempt, proto_fuzz, firewall_trace, threat_feed,
    s3_enum, cloud_auth, instance_map, cloud_events,
    fs_tree, fs_search, shadow_files, mount_enum,
    hash_crack, rsa_probe, key_enum, entropy_check,
    ai_inspect, ai_trace, ai_memory,
    kern_dump, kern_trace, syscall_map,
    onion_scan, relay_trace, darknet_pulse
]

def infinite_overtrace():
    global running_loops
    while running_loops:
        func = random.choice(modules_list)
        func()
        time.sleep(0.3)

def start_overtrace():
    global running_loops
    running_loops = True
    t = threading.Thread(target=infinite_overtrace)
    t.daemon = True
    t.start()
    slow("[overtrace started]")

def stop_overtrace():
    global running_loops
    running_loops = False
    slow("[overtrace stopped]")

# ------------------------------------
# SCAN (AI-like scan)
# ------------------------------------

def scan(target="unknown"):
    line()
    slow(f"Scanning target: {target}")
    for i in range(12):
        slow(f"[scan] layer {i+1}/12 → {rand_ip()} entropy={random.randint(1000,9999)}")
    line()

# ------------------------------------
# COMMAND ROUTER
# ------------------------------------

commands = {
    "scan": scan,
    "sysinfo": sysinfo,
    "syscheck": syscheck,
    "sysmon": sysmon,
    "memmap": memmap,
    "cpu_heat": cpu_heat,
    "kern_events": kern_events,
    "netmap": netmap,
    "netstat": netstat,
    "netprobe": netprobe,
    "route_scan": route_scan,
    "dns_lookup": dns_lookup,
    "arp_enum": arp_enum,
    "vulnscan": vulnscan,
    "portscan": portscan,
    "breach_attempt": breach_attempt,
    "proto_fuzz": proto_fuzz,
    "firewall_trace": firewall_trace,
    "threat_feed": threat_feed,
    "s3_enum": s3_enum,
    "cloud_auth": cloud_auth,
    "instance_map": instance_map,
    "cloud_events": cloud_events,
    "fs_tree": fs_tree,
    "fs_search": fs_search,
    "shadow_files": shadow_files,
    "mount_enum": mount_enum,
    "hash_crack": hash_crack,
    "rsa_probe": rsa_probe,
    "key_enum": key_enum,
    "entropy_check": entropy_check,
    "ai_inspect": ai_inspect,
    "ai_trace": ai_trace,
    "ai_memory": ai_memory,
    "kern_dump": kern_dump,
    "kern_trace": kern_trace,
    "syscall_map": syscall_map,
    "onion_scan": onion_scan,
    "relay_trace": relay_trace,
    "darknet_pulse": darknet_pulse,
    "overtrace": start_overtrace,
    "stop": stop_overtrace
}

def run_cmd(cmd):
    if not cmd.strip():
        return
    parts = cmd.split()
    name = parts[0]

    if name == "scan" and len(parts) > 1:
        scan(" ".join(parts[1:]))
        return

    if name in commands:
        commands[name]()
    else:
        slow("Unknown command")

# ------------------------------------
# MAIN LOOP
# ------------------------------------

def main():
    slow("Terminal loaded.")
    while True:
        try:
            cmd = input("> ")
            run_cmd(cmd)
        except KeyboardInterrupt:
            stop_overtrace()
            slow("exit.")
            sys.exit()

if __name__ == "__main__":
    main()
