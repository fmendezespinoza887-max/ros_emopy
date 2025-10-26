#!/usr/bin/env python3
# fgm_network_guard.py
# Prototipo defensivo: detección, ledger y tickets para aislar dispositivos no autorizados
# Uso responsable: diseñado para la red de Fernando Guadalupe Mendez Espinoza.
# Requiere revisión humana para ejecutar acciones de bloqueo (2 aprobaciones).

import os
import sys
import json
import time
import hashlib
import socket
import subprocess
from pathlib import Path
from datetime import datetime

# Optional imports - use if available
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY = True
except Exception:
    SCAPY = False

WORKDIR = Path.cwd() / "fgm_network_guard"
WORKDIR.mkdir(parents=True, exist_ok=True)
LEDGER = WORKDIR / "fgm_network_ledger.json"
TICKETS_DIR = WORKDIR / "tickets"
TICKETS_DIR.mkdir(parents=True, exist_ok=True)
AUTH_FILE = WORKDIR / "authorized.json"   # contiene diccionario con MACs/IPs autorizadas
APPROVALS_DIR = WORKDIR / "approvals"
APPROVALS_DIR.mkdir(parents=True, exist_ok=True)

# CONFIGURACIÓN
SUBNET = "192.168.1.0/24"   # Ajusta a tu red
SCAN_INTERVAL = 60          # segundos
ADMIN_EMAILS = ["admin1@example.com","admin2@example.com"]  # para notificaciones (opcional)
# política: requiere dos aprobaciones (por defecto) para ejecutar comandos de bloqueo
REQUIRED_APPROVALS = 2

# Helpers
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def load_authorized():
    if AUTH_FILE.exists():
        try:
            return json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {"macs": [], "ips": [], "notes": {}}
    else:
        # plantilla inicial
        data = {"macs": [], "ips": [], "notes": {}}
        AUTH_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data

def save_authorized(a):
    AUTH_FILE.write_text(json.dumps(a, indent=2), encoding="utf-8")
    os.chmod(AUTH_FILE, 0o600)

def append_ledger(entry):
    ledger = []
    if LEDGER.exists():
        try:
            ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        except Exception:
            ledger = []
    ledger.append(entry)
    LEDGER.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    os.chmod(LEDGER, 0o600)

def sha256_of(obj):
    j = json.dumps(obj, sort_keys=True, separators=(',',':')).encode('utf-8')
    return hashlib.sha256(j).hexdigest()

# Network scan (uses scapy if available; otherwise fallback to 'arp -a' + ping sweep)
def arp_scan(subnet):
    results = []
    if SCAPY:
        conf.verb = 0
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet)
            ans, _ = srp(pkt, timeout=2, iface_hint=subnet)
            for s,r in ans:
                ip = r.psrc
                mac = r.hwsrc.lower()
                results.append({"ip": ip, "mac": mac})
            return results
        except Exception as e:
            print("scapy error:", e)
    # fallback: try system arp table + ping sweep
    try:
        # ping sweep
        net = subnet.split('/')[0]
        # Basic ping of common hosts: (not exhaustive)
        base = ".".join(net.split('.')[:3]) + "."
        for i in range(1,255):
            ip = base + str(i)
            try:
                subprocess.run(["ping","-c","1","-W","1",ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        # read arp table
        out = subprocess.check_output(["arp","-a"], universal_newlines=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                hostname = parts[0]
                ip = parts[1].strip("()")
                mac = parts[3].lower()
                results.append({"ip": ip, "mac": mac})
    except Exception:
        pass
    return results

# Generate recommendations to isolate device (do NOT execute)
def generate_isolation_commands(device):
    ip = device.get("ip")
    mac = device.get("mac")
    cmds = {
        "iptables_block_ip": f"sudo iptables -I FORWARD -s {ip} -j DROP",
        "iptables_block_mac": f"sudo iptables -I FORWARD -m mac --mac-source {mac} -j DROP",
        "nftables_block_ip": f"sudo nft add rule inet filter forward ip saddr {ip} drop",
        "router_api_example": f"curl -X POST -u 'ROUTER_USER:ROUTER_PASS' 'http://ROUTER_IP/api/block' -d '{{\"mac\":\"{mac}\", \"ip\":\"{ip}\"}}'",
        "dhcp_blacklist": f"Agregar {mac} en la lista de bloqueo DHCP del servidor/router",
        "vlan_isolation_note": "Mover puerto/dispositivo a VLAN de cuarentena en switch gestionado"
    }
    return cmds

# Ticket creation requires 2 approvals to execute
def create_ticket(device, reason, recommended_cmds):
    entry = {
        "ts": now_iso(),
        "action": "detect_unauthorized_device",
        "device": device,
        "reason": reason,
        "recommended_cmds": recommended_cmds
    }
    entry["sha256"] = sha256_of(entry)
    # ledger append
    append_ledger(entry)
    # write ticket file
    tid = entry["sha256"][:12]
    tfile = TICKETS_DIR / f"ticket_{tid}.json"
    tfile.write_text(json.dumps(entry, indent=2), encoding="utf-8")
    os.chmod(tfile, 0o660)
    print(f"[TICKET] {tfile} creado. Requiere {REQUIRED_APPROVALS} aprobaciones en {APPROVALS_DIR}/ticket_{tid}.approvals")
    # create empty approvals file
    (APPROVALS_DIR / f"ticket_{tid}.approvals").write_text(json.dumps([], indent=2), encoding="utf-8")
    return tfile

def add_approval(ticket_sha, approver):
    apfile = APPROVALS_DIR / f"ticket_{ticket_sha[:12]}.approvals"
    if not apfile.exists():
        print("Ticket approvals file no existe.")
        return False
    arr = json.loads(apfile.read_text(encoding="utf-8"))
    if approver in arr:
        print("Ya aprobó este usuario.")
        return False
    arr.append({"approver": approver, "ts": now_iso()})
    apfile.write_text(json.dumps(arr, indent=2), encoding="utf-8")
    print(f"Aprobación añadida por {approver}. Total aprobaciones: {len(arr)}")
    return len(arr) >= REQUIRED_APPROVALS

def process_scan(authorized):
    devices = arp_scan(SUBNET)
    seen_macs = set()
    for d in devices:
        mac = d.get("mac")
        ip = d.get("ip")
        seen_macs.add(mac)
        authorized_macs = [m.lower() for m in authorized.get("macs",[])]
        authorized_ips = [i for i in authorized.get("ips",[])]
        if (mac not in authorized_macs) and (ip not in authorized_ips):
            reason = "MAC/IP no autorizada en lista blanca"
            cmds = generate_isolation_commands(d)
            create_ticket(d, reason, cmds)
        else:
            # log clean sighting
            entry = {"ts": now_iso(), "action":"sighting", "device": d}
            entry["sha256"] = sha256_of(entry)
            append_ledger(entry)
    # Optionally detect authorized devices that went offline etc.
    # Return devices for UI or further processing
    return devices

def main_loop():
    print("FGM Network Guard - prototipo iniciado")
    print(f"Subred: {SUBNET} | Intervalo escaneo: {SCAN_INTERVAL}s")
    authorized = load_authorized()
    print("Dispositivos autorizados cargados:", len(authorized.get("macs",[])), "MACs")
    try:
        while True:
            devices = process_scan(authorized)
            # sleep
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("Interrumpido por usuario. Saliendo.")
    except Exception as e:
        print("Error principal:", e)

if __name__ == "__main__":
    main_loop()
