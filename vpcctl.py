#!/usr/bin/env python3
"""
vpcctl.py - Lightweight Linux VPC simulator (single-file)

Features:
 - create-vpc --name NAME --cidr CIDR --internet-interface IF
 - add-subnet --vpc NAME --name SUBNET --cidr CIDR --type public|private
 - delete-subnet --vpc NAME --name SUBNET
 - delete-vpc --name NAME  (robust cleanup including orphaned namespaces)
 - apply-policy --policy PATH.json  (JSON firewall policy applied inside namespace)
 - peer --vpc-a A --vpc-b B --allowed-cidrs CIDR1,CIDR2  (creates a veth between bridges)
 - unpeer --vpc-a A --vpc-b B
 - list
Notes: run as root (sudo). Uses native Linux tools: ip, iptables, bridge.
"""

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys

# ---------- logging ----------
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger("vpcctl")

# ---------- helpers ----------
def run_cmd(cmd, check=True, capture=False):
    """Run a shell command. cmd may be list or string."""
    if isinstance(cmd, str):
        cmd_list = shlex.split(cmd)
    else:
        cmd_list = cmd
    log.debug("RUN: %s", " ".join(cmd_list))
    if capture:
        result = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result
    else:
        return subprocess.run(cmd_list, check=check)

def exists_ip_link(name):
    return subprocess.run(["ip", "link", "show", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def list_netns():
    r = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    return lines

def exists_netns(name):
    return name in list_netns()

def ensure_ip_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    log.info("IP forwarding enabled for session (sysctl net.ipv4.ip_forward=1). To persist, edit /etc/sysctl.conf")

# ---------- naming ----------

import hashlib

def short_hash(s, n=3):
    return hashlib.md5(s.encode()).hexdigest()[:n]

def br_name(vpc):
    return f"br-{vpc}"

def ns_name(vpc, subnet):
    return f"ns-{vpc}-{subnet}"

def veth_host_name(vpc, subnet):
    h = short_hash(vpc + subnet, 3)
    return f"veth-{h}-h"

def veth_ns_name(vpc, subnet):
    h = short_hash(vpc + subnet, 3)
    return f"veth-{h}-n"

def peer_ifname(a,b,side):
    # shorten ifnames to stay under Linux 15-char limit
    a_short = a[:3]
    b_short = b[:3]
    return f"pr-{a_short}-{b_short}-{side}"

# ---------- VPC CRUD ----------
META_DIR = "/var/lib/vpcctl"
os.makedirs(META_DIR, exist_ok=True)

def meta_file_for(vpc):
    return os.path.join(META_DIR, f"{vpc}.json")

def save_meta(vpc, meta):
    with open(meta_file_for(vpc), "w") as f:
        json.dump(meta, f)

def load_meta(vpc):
    mf = meta_file_for(vpc)
    if os.path.exists(mf):
        with open(mf) as f:
            return json.load(f)
    return None

def create_vpc(args):
    vpc = args.name
    cidr = args.cidr
    internet_if = args.internet_interface
    bridge = br_name(vpc)

    log.info("Creating VPC '%s' CIDR=%s internet_if=%s", vpc, cidr, internet_if)

    if not exists_ip_link(bridge):
        run_cmd(["ip", "link", "add", "name", bridge, "type", "bridge"], check=False)
        run_cmd(["ip", "link", "set", bridge, "up"], check=False)
        log.info("Created bridge %s", bridge)
    else:
        log.info("Bridge %s already exists", bridge)

    meta = {"name": vpc, "cidr": cidr, "internet_interface": internet_if, "subnets": {}}
    old = load_meta(vpc)
    if old and isinstance(old.get("subnets"), dict):
        meta["subnets"] = old["subnets"]
    save_meta(vpc, meta)
    log.info("Saved metadata %s", meta_file_for(vpc))

def add_subnet(args):
    vpc = args.vpc
    name = args.name
    cidr = args.cidr
    stype = args.type.lower()
    bridge = br_name(vpc)

    mf = meta_file_for(vpc)
    if not os.path.exists(mf):
        log.error("VPC metadata missing. Create VPC first.")
        sys.exit(1)
    meta = load_meta(vpc)

    ns = ns_name(vpc, name)
    veth_h = veth_host_name(vpc, name)
    veth_n = veth_ns_name(vpc, name)

    # namespace
    if not exists_netns(ns):
        run_cmd(["ip", "netns", "add", ns], check=False)
        log.info("Created namespace %s", ns)
    else:
        log.info("Namespace %s already exists", ns)

    # veth pair
    if not exists_ip_link(veth_h) and not exists_ip_link(veth_n):
        run_cmd(["ip", "link", "add", veth_h, "type", "veth", "peer", "name", veth_n], check=False)
        log.info("Created veth pair %s <-> %s", veth_h, veth_n)
    else:
        log.info("veth pair %s/%s exists, skipping create", veth_h, veth_n)

    # attach host veth to bridge
    run_cmd(["ip", "link", "set", veth_h, "master", bridge], check=False)
    run_cmd(["ip", "link", "set", veth_h, "up"], check=False)

    # move ns end into namespace and rename to eth0
    run_cmd(["ip", "link", "set", veth_n, "netns", ns], check=False)
    run_cmd(["ip", "netns", "exec", ns, "ip", "link", "set", "dev", veth_n, "name", "eth0"], check=False)
    run_cmd(["ip", "netns", "exec", ns, "ip", "link", "set", "eth0", "up"], check=False)

    # assign ips (gateway .1 to bridge, host .10 in namespace)
    base, prefix = cidr.split("/")
    o = base.split(".")
    gw = f"{o[0]}.{o[1]}.{o[2]}.1/{prefix}"
    host = f"{o[0]}.{o[1]}.{o[2]}.10/{prefix}"
    gw_ip = gw.split("/")[0]

    # assign gateway to bridge if not present
    r = run_cmd(["ip", "addr", "show", "dev", bridge], capture=True)
    if gw_ip not in (r.stdout + r.stderr):
        run_cmd(["ip", "addr", "add", gw, "dev", bridge], check=False)
        log.info("Assigned gateway %s to %s", gw, bridge)
    else:
        log.info("Bridge %s already has IP %s", bridge, gw_ip)

    # assign host ip to namespace
    rns = run_cmd(["ip", "netns", "exec", ns, "ip", "addr", "show", "dev", "eth0"], capture=True)
    if host.split("/")[0] not in (rns.stdout + rns.stderr):
        run_cmd(["ip", "netns", "exec", ns, "ip", "addr", "add", host, "dev", "eth0"], check=False)
        log.info("Assigned %s to %s:eth0", host, ns)
    else:
        log.info("Namespace %s already has IP %s", ns, host)

    # default route
    run_cmd(["ip", "netns", "exec", ns, "ip", "route", "del", "default"], check=False)
    run_cmd(["ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", gw_ip, "dev", "eth0"], check=False)
    log.info("Set default route in %s via %s", ns, gw_ip)

    # update meta
    meta["subnets"][name] = {"cidr": cidr, "type": stype}
    save_meta(vpc, meta)
    log.info("Updated metadata for VPC %s", vpc)

    # NAT for public
    if stype == "public":
        internet_if = meta.get("internet_interface")
        if not internet_if:
            log.warning("No internet_interface in metadata; NAT not configured.")
        else:
            add_nat_for_subnet(internet_if, cidr, bridge)

def delete_subnet(args):
    vpc = args.vpc
    name = args.name
    ns = ns_name(vpc, name)
    veth_h = veth_host_name(vpc, name)
    log.info("Deleting subnet %s from VPC %s", name, vpc)

    # delete namespace
    if exists_netns(ns):
        run_cmd(["ip", "netns", "delete", ns], check=False)
        log.info("Deleted namespace %s", ns)
    else:
        log.info("Namespace %s not present", ns)

    # delete host veth
    if exists_ip_link(veth_h):
        run_cmd(["ip", "link", "delete", veth_h], check=False)
        log.info("Deleted veth %s", veth_h)
    else:
        log.info("Host veth %s not present", veth_h)

    # remove metadata entry
    mf = meta_file_for(vpc)
    if os.path.exists(mf):
        meta = load_meta(vpc)
        meta.get("subnets", {}).pop(name, None)
        save_meta(vpc, meta)
        log.info("Updated metadata removed subnet %s", name)

# ---------- NAT ----------
def add_nat_for_subnet(internet_if, subnet_cidr, bridge_if):
    log.info("Configuring NAT for subnet %s out via %s", subnet_cidr, internet_if)
    # add MASQUERADE; idempotency handled by -C check omitted, we do best-effort dedupe
    run_cmd(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet_cidr, "-o", internet_if, "-j", "MASQUERADE"], check=False)
    run_cmd(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet_cidr, "-o", internet_if, "-j", "MASQUERADE"], check=False)
    run_cmd(["iptables", "-C", "FORWARD", "-i", bridge_if, "-o", internet_if, "-j", "ACCEPT"], check=False)
    run_cmd(["iptables", "-A", "FORWARD", "-i", bridge_if, "-o", internet_if, "-j", "ACCEPT"], check=False)
    run_cmd(["iptables", "-C", "FORWARD", "-i", internet_if, "-o", bridge_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
    run_cmd(["iptables", "-A", "FORWARD", "-i", internet_if, "-o", bridge_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
    log.info("NAT and forwarding rules applied (best-effort)")

def remove_nat_for_subnet(internet_if, subnet_cidr, bridge_if):
    log.info("Removing NAT rules for %s", subnet_cidr)
    run_cmd(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet_cidr, "-o", internet_if, "-j", "MASQUERADE"], check=False)
    run_cmd(["iptables", "-D", "FORWARD", "-i", bridge_if, "-o", internet_if, "-j", "ACCEPT"], check=False)
    run_cmd(["iptables", "-D", "FORWARD", "-i", internet_if, "-o", bridge_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
    log.info("Removed NAT & forwarding rules (best-effort)")

# ---------- VPC deletion (robust) ----------
def delete_vpc(args):
    vpc = args.name
    log.info("Deleting VPC '%s'", vpc)
    mf = meta_file_for(vpc)
    meta = load_meta(vpc) or {"subnets": {}}

    # delete subnets listed in metadata
    for s in list(meta.get("subnets", {}).keys()):
        try:
            delete_subnet(argparse.Namespace(vpc=vpc, name=s))
        except Exception as e:
            log.warning("Error deleting subnet %s: %s", s, e)

    # remove bridge
    bridge = br_name(vpc)
    if exists_ip_link(bridge):
        run_cmd(["ip", "link", "set", bridge, "down"], check=False)
        run_cmd(["ip", "link", "delete", bridge, "type", "bridge"], check=False)
        log.info("Deleted bridge %s", bridge)
    else:
        log.info("Bridge %s not present", bridge)

    # remove metadata
    if os.path.exists(mf):
        try:
            os.remove(mf)
            log.info("Removed metadata %s", mf)
        except Exception as e:
            log.warning("Could not remove %s: %s", mf, e)

    # safety-net: delete any orphaned namespaces matching vpc prefix
    try:
        for ns in list_netns():
            nsname = ns.split()[0]
            if nsname.startswith(f"ns-{vpc}-"):
                run_cmd(["ip", "netns", "delete", nsname], check=False)
                log.info("Deleted orphaned namespace %s", nsname)
    except Exception as e:
        log.warning("Orphan cleanup failed: %s", e)

    log.info("VPC '%s' fully deleted.", vpc)

# ---------- Firewall policy ----------
def apply_policy(args):
    pf = args.policy
    if not os.path.exists(pf):
        log.error("Policy file %s not found", pf); sys.exit(1)
    with open(pf) as f:
        policy = json.load(f)
    subnet = policy.get("subnet")
    if not subnet:
        log.error("Policy missing 'subnet' field"); sys.exit(1)

    # find namespace via metadata
    found = False
    for fn in os.listdir(META_DIR) if os.path.exists(META_DIR) else []:
        if not fn.endswith(".json"):
            continue
        with open(os.path.join(META_DIR, fn)) as f:
            meta = json.load(f)
        for sname, sdata in meta.get("subnets", {}).items():
            if sdata.get("cidr") == subnet:
                ns = ns_name(meta["name"], sname)
                found = True
                break
        if found:
            break
    if not found:
        log.error("No subnet metadata found matching %s", subnet); sys.exit(1)

    apply_policy_to_ns(ns, policy)

def apply_policy_to_ns(ns, policy):
    log.info("Applying policy to namespace %s", ns)
    # reset chains
    run_cmd(f"ip netns exec {ns} iptables -F", check=False)
    run_cmd(f"ip netns exec {ns} iptables -X", check=False)
    run_cmd(f"ip netns exec {ns} iptables -P INPUT DROP", check=False)
    run_cmd(f"ip netns exec {ns} iptables -P OUTPUT ACCEPT", check=False)
    # allow loopback & established
    run_cmd(f"ip netns exec {ns} iptables -A INPUT -i lo -j ACCEPT", check=False)
    run_cmd(f"ip netns exec {ns} iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT", check=False)
    # apply ingress rules
    for r in policy.get("ingress", []):
        port = r.get("port")
        proto = r.get("protocol", "tcp")
        action = r.get("action", "allow").lower()
        if port in ("any", "ANY"):
            port_args = []
        else:
            port_args = ["--dport", str(port)]
        jump = "ACCEPT" if action == "allow" else "DROP"
        cmd = ["ip", "netns", "exec", ns, "iptables", "-A", "INPUT", "-p", proto] + port_args + ["-j", jump]
        run_cmd(cmd, check=False)
    log.info("Policy applied")

# ---------- Peering ----------
def peer_vpcs(args):
    a, b = args.vpc_a, args.vpc_b
    allowed = [c.strip() for c in args.allowed_cidrs.split(",") if c.strip()] if args.allowed_cidrs else []
    br_a, br_b = br_name(a), br_name(b)
    if not exists_ip_link(br_a) or not exists_ip_link(br_b):
        log.error("Both bridges must exist to peer"); sys.exit(1)
    if_a = peer_ifname(a,b,'a'); if_b = peer_ifname(a,b,'b')
    if not exists_ip_link(if_a):
        run_cmd(["ip", "link", "add", if_a, "type", "veth", "peer", "name", if_b], check=False)
        log.info("Created peering interfaces %s <-> %s", if_a, if_b)
    run_cmd(["ip", "link", "set", if_a, "master", br_a], check=False)
    run_cmd(["ip", "link", "set", if_b, "master", br_b], check=False)
    run_cmd(["ip", "link", "set", if_a, "up"], check=False)
    run_cmd(["ip", "link", "set", if_b, "up"], check=False)

    # add host routes for allowed CIDRs via the peering interfaces
    for cidr in allowed:
        run_cmd(["ip", "route", "replace", cidr, "dev", if_a], check=False)
        run_cmd(["ip", "route", "replace", cidr, "dev", if_b], check=False)
    log.info("Peering established between %s and %s (allowed: %s)", a, b, allowed)

def unpeer_vpcs(args):
    a, b = args.vpc_a, args.vpc_b
    for ifname in [peer_ifname(a,b,'a'), peer_ifname(a,b,'b')]:
        if exists_ip_link(ifname):
            run_cmd(["ip", "link", "delete", ifname], check=False)
            log.info("Deleted peering interface %s", ifname)
    log.info("Peering removed between %s and %s", a, b)

# ---------- listing ----------
def list_vpcs(args):
    if not os.path.exists(META_DIR):
        print("No VPCs found.")
        return
    for fn in sorted(os.listdir(META_DIR)):
        if not fn.endswith(".json"): continue
        with open(os.path.join(META_DIR, fn)) as f:
            meta = json.load(f)
        print(f"VPC: {meta.get('name')} CIDR: {meta.get('cidr')} IF: {meta.get('internet_interface')}")
        for sname, sdata in meta.get("subnets", {}).items():
            print(f"  Subnet: {sname} CIDR: {sdata.get('cidr')} TYPE: {sdata.get('type')} NS: {ns_name(meta['name'], sname)}")

# ---------- CLI ----------
def build_parser():
    p = argparse.ArgumentParser(prog="vpcctl", description="Lightweight VPC simulator")
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("create-vpc"); c.add_argument("--name", required=True); c.add_argument("--cidr", required=True); c.add_argument("--internet-interface", required=True); c.set_defaults(func=create_vpc)
    a = sub.add_parser("add-subnet"); a.add_argument("--vpc", required=True); a.add_argument("--name", required=True); a.add_argument("--cidr", required=True); a.add_argument("--type", choices=["public","private"], required=True); a.set_defaults(func=add_subnet)
    sd = sub.add_parser("delete-subnet"); sd.add_argument("--vpc", required=True); sd.add_argument("--name", required=True); sd.set_defaults(func=delete_subnet)
    d = sub.add_parser("delete-vpc"); d.add_argument("--name", required=True); d.set_defaults(func=delete_vpc)
    ppol = sub.add_parser("apply-policy"); ppol.add_argument("--policy", required=True); ppol.set_defaults(func=apply_policy)
    pp = sub.add_parser("peer"); pp.add_argument("--vpc-a", required=True); pp.add_argument("--vpc-b", required=True); pp.add_argument("--allowed-cidrs", required=False, default=""); pp.set_defaults(func=peer_vpcs)
    un = sub.add_parser("unpeer"); un.add_argument("--vpc-a", required=True); un.add_argument("--vpc-b", required=True); un.set_defaults(func=unpeer_vpcs)
    l = sub.add_parser("list"); l.set_defaults(func=list_vpcs)

    return p

def main():
    if os.geteuid() != 0:
        log.error("This tool must be run as root.")
        sys.exit(1)
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)
    ensure_ip_forwarding()
    try:
        args.func(args)
    except subprocess.CalledProcessError as e:
        log.exception("Command failed: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()