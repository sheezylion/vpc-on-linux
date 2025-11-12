#!/usr/bin/env python3
"""
vpcctl.py - Lightweight Linux VPC simulator (improved isolated version)

Improvements:
 - Enforces isolation between VPC bridges (prevents cross-VPC traffic without peering)
 - Cleans and re-adds NAT rules safely (no duplication)
 - Removes NAT rules when deleting VPCs
 - Improved logging clarity
"""

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
import hashlib

# ---------- logging ----------
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger("vpcctl")

# ---------- helpers ----------
def run_cmd(cmd, check=True, capture=False):
    if isinstance(cmd, str):
        cmd_list = shlex.split(cmd)
    else:
        cmd_list = cmd
    log.debug("RUN: %s", " ".join(cmd_list))
    if capture:
        return subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    else:
        return subprocess.run(cmd_list, check=check)

def exists_ip_link(name):
    return subprocess.run(["ip", "link", "show", name],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def list_netns():
    r = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]

def exists_netns(name):
    return name in list_netns()

def ensure_ip_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    log.info("IP forwarding enabled for session.")

# ---------- naming ----------
def short_hash(s, n=3):
    return hashlib.md5(s.encode()).hexdigest()[:n]

def br_name(vpc): return f"br-{vpc}"
def ns_name(vpc, subnet): return f"ns-{vpc}-{subnet}"
def veth_host_name(vpc, subnet): return f"veth-{short_hash(vpc+subnet)}-h"
def veth_ns_name(vpc, subnet): return f"veth-{short_hash(vpc+subnet)}-n"

def peer_ifname(a,b,side):
    return f"pr-{a[:3]}-{b[:3]}-{side}"

# ---------- metadata ----------
META_DIR = "/var/lib/vpcctl"
os.makedirs(META_DIR, exist_ok=True)

def meta_file_for(vpc): return os.path.join(META_DIR, f"{vpc}.json")

def save_meta(vpc, meta):
    with open(meta_file_for(vpc), "w") as f: json.dump(meta, f)

def load_meta(vpc):
    mf = meta_file_for(vpc)
    if os.path.exists(mf):
        with open(mf) as f: return json.load(f)
    return None

# ---------- isolation ----------
def enforce_bridge_isolation():
    """Block traffic between bridges unless peered."""
    try:
        existing = subprocess.run(["iptables", "-S", "FORWARD"], capture_output=True, text=True).stdout
        if "-j DROP" in existing and "br-" in existing:
            return
        run_cmd(["iptables", "-A", "FORWARD", "-i", "br-*", "-o", "br-*", "-j", "DROP"], check=False)
        log.info("Bridge-to-bridge isolation enforced.")
    except Exception as e:
        log.warning("Could not enforce bridge isolation: %s", e)

# ---------- VPC CRUD ----------
def create_vpc(args):
    vpc, cidr, internet_if = args.name, args.cidr, args.internet_interface
    bridge = br_name(vpc)
    log.info(f"Creating VPC {vpc} CIDR={cidr} via {internet_if}")

    if not exists_ip_link(bridge):
        run_cmd(["ip", "link", "add", bridge, "type", "bridge"], check=False)
        run_cmd(["ip", "link", "set", bridge, "up"], check=False)
        log.info(f"Created bridge {bridge}")
    else:
        log.info(f"Bridge {bridge} already exists")

    meta = {"name": vpc, "cidr": cidr, "internet_interface": internet_if, "subnets": {}}
    old = load_meta(vpc)
    if old and "subnets" in old:
        meta["subnets"] = old["subnets"]
    save_meta(vpc, meta)

    enforce_bridge_isolation()
    log.info(f"Metadata saved for VPC {vpc}")

def add_subnet(args):
    vpc, name, cidr, stype = args.vpc, args.name, args.cidr, args.type.lower()
    bridge = br_name(vpc)
    mf = meta_file_for(vpc)
    if not os.path.exists(mf):
        log.error("VPC not found. Create it first."); sys.exit(1)
    meta = load_meta(vpc)

    ns = ns_name(vpc, name)
    veth_h, veth_n = veth_host_name(vpc, name), veth_ns_name(vpc, name)

    # namespace
    if not exists_netns(ns):
        run_cmd(["ip", "netns", "add", ns], check=False)
        log.info(f"Created namespace {ns}")

    # veth pair
    if not exists_ip_link(veth_h) and not exists_ip_link(veth_n):
        run_cmd(["ip", "link", "add", veth_h, "type", "veth", "peer", "name", veth_n], check=False)
        log.info(f"Created veth pair {veth_h} <-> {veth_n}")

    run_cmd(["ip", "link", "set", veth_h, "master", bridge], check=False)
    run_cmd(["ip", "link", "set", veth_h, "up"], check=False)

    run_cmd(["ip", "link", "set", veth_n, "netns", ns], check=False)
    run_cmd(["ip", "netns", "exec", ns, "ip", "link", "set", veth_n, "name", "eth0"], check=False)
    run_cmd(["ip", "netns", "exec", ns, "ip", "link", "set", "eth0", "up"], check=False)

    base, prefix = cidr.split("/")
    o = base.split(".")
    gw, host = f"{o[0]}.{o[1]}.{o[2]}.1/{prefix}", f"{o[0]}.{o[1]}.{o[2]}.10/{prefix}"
    gw_ip = gw.split("/")[0]

    r = run_cmd(["ip", "addr", "show", "dev", bridge], capture=True)
    if gw_ip not in r.stdout:
        run_cmd(["ip", "addr", "add", gw, "dev", bridge], check=False)
        log.info(f"Assigned {gw} to {bridge}")

    run_cmd(["ip", "netns", "exec", ns, "ip", "addr", "add", host, "dev", "eth0"], check=False)
    run_cmd(["ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", gw_ip, "dev", "eth0"], check=False)
    log.info(f"Default route via {gw_ip} in {ns}")

    meta["subnets"][name] = {"cidr": cidr, "type": stype}
    save_meta(vpc, meta)

    if stype == "public":
        inet = meta.get("internet_interface")
        if inet:
            add_nat_for_subnet(inet, cidr, bridge)
        else:
            log.warning("No internet interface; NAT skipped.")

def delete_subnet(args):
    vpc, name = args.vpc, args.name
    ns, veth_h = ns_name(vpc, name), veth_host_name(vpc, name)
    log.info(f"Deleting subnet {name} in {vpc}")

    if exists_netns(ns):
        run_cmd(["ip", "netns", "delete", ns], check=False)
    if exists_ip_link(veth_h):
        run_cmd(["ip", "link", "delete", veth_h], check=False)

    meta = load_meta(vpc) or {}
    meta.get("subnets", {}).pop(name, None)
    save_meta(vpc, meta)

# ---------- NAT ----------
def add_nat_for_subnet(inet_if, subnet_cidr, bridge_if):
    log.info(f"Applying NAT for {subnet_cidr} via {inet_if}")
    for cmd in [
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet_cidr, "-o", inet_if, "-j", "MASQUERADE"],
        ["iptables", "-D", "FORWARD", "-i", bridge_if, "-o", inet_if, "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-i", inet_if, "-o", bridge_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]
    ]:
        run_cmd(cmd, check=False)

    run_cmd(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet_cidr, "-o", inet_if, "-j", "MASQUERADE"], check=False)
    run_cmd(["iptables", "-A", "FORWARD", "-i", bridge_if, "-o", inet_if, "-j", "ACCEPT"], check=False)
    run_cmd(["iptables", "-A", "FORWARD", "-i", inet_if, "-o", bridge_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
    log.info(f"NAT configured for {subnet_cidr}")

def remove_nat_for_bridge(bridge_if):
    run_cmd(["iptables", "-D", "FORWARD", "-i", bridge_if, "-j", "ACCEPT"], check=False)
    run_cmd(["iptables", "-D", "FORWARD", "-o", bridge_if, "-j", "ACCEPT"], check=False)
    log.info(f"Cleaned NAT rules for {bridge_if}")

# ---------- VPC deletion ----------
def delete_vpc(args):
    vpc = args.name
    bridge = br_name(vpc)
    log.info(f"Deleting VPC {vpc}")
    meta = load_meta(vpc) or {"subnets": {}}

    for s in list(meta.get("subnets", {}).keys()):
        try:
            delete_subnet(argparse.Namespace(vpc=vpc, name=s))
        except Exception as e:
            log.warning(f"Error deleting subnet {s}: {e}")

    remove_nat_for_bridge(bridge)

    if exists_ip_link(bridge):
        run_cmd(["ip", "link", "set", bridge, "down"], check=False)
        run_cmd(["ip", "link", "delete", bridge, "type", "bridge"], check=False)
        log.info(f"Deleted bridge {bridge}")

    mf = meta_file_for(vpc)
    if os.path.exists(mf):
        os.remove(mf)
        log.info(f"Metadata {mf} removed")

    for ns in list_netns():
        if ns.startswith(f"ns-{vpc}-"):
            run_cmd(["ip", "netns", "delete", ns], check=False)
            log.info(f"Removed orphan namespace {ns}")

    log.info(f"VPC {vpc} deleted successfully")

# ---------- Peering ----------
def peer_vpcs(args):
    a, b = args.vpc_a, args.vpc_b
    allowed = [c.strip() for c in args.allowed_cidrs.split(",") if c.strip()] if args.allowed_cidrs else []
    br_a, br_b = br_name(a), br_name(b)
    if not exists_ip_link(br_a) or not exists_ip_link(br_b):
        log.error("Both bridges must exist."); sys.exit(1)

    if_a, if_b = peer_ifname(a,b,"a"), peer_ifname(a,b,"b")
    if not exists_ip_link(if_a):
        run_cmd(["ip", "link", "add", if_a, "type", "veth", "peer", "name", if_b], check=False)
        log.info(f"Peering interfaces {if_a}<->{if_b} created")

    run_cmd(["ip", "link", "set", if_a, "master", br_a], check=False)
    run_cmd(["ip", "link", "set", if_b, "master", br_b], check=False)
    run_cmd(["ip", "link", "set", if_a, "up"], check=False)
    run_cmd(["ip", "link", "set", if_b, "up"], check=False)

    for cidr in allowed:
        run_cmd(["ip", "route", "replace", cidr, "dev", if_a], check=False)
        run_cmd(["ip", "route", "replace", cidr, "dev", if_b], check=False)
    log.info(f"Peering between {a} and {b} established.")

def unpeer_vpcs(args):
    a,b = args.vpc_a, args.vpc_b
    for ifn in [peer_ifname(a,b,"a"), peer_ifname(a,b,"b")]:
        if exists_ip_link(ifn):
            run_cmd(["ip", "link", "delete", ifn], check=False)
            log.info(f"Removed peering iface {ifn}")
    log.info(f"Peering removed between {a} and {b}")

# ---------- listing ----------
def list_vpcs(args):
    if not os.path.exists(META_DIR):
        print("No VPCs found."); return
    for fn in sorted(os.listdir(META_DIR)):
        if not fn.endswith(".json"): continue
        with open(os.path.join(META_DIR, fn)) as f: meta = json.load(f)
        print(f"VPC: {meta.get('name')} CIDR: {meta.get('cidr')} IF: {meta.get('internet_interface')}")
        for sname, sdata in meta.get("subnets", {}).items():
            print(f"  Subnet: {sname} CIDR: {sdata.get('cidr')} TYPE: {sdata.get('type')} NS: {ns_name(meta['name'], sname)}")

# ---------- CLI ----------
def build_parser():
    p = argparse.ArgumentParser(prog="vpcctl", description="Lightweight Linux VPC simulator")
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("create-vpc"); c.add_argument("--name", required=True); c.add_argument("--cidr", required=True); c.add_argument("--internet-interface", required=True); c.set_defaults(func=create_vpc)
    a = sub.add_parser("add-subnet"); a.add_argument("--vpc", required=True); a.add_argument("--name", required=True); a.add_argument("--cidr", required=True); a.add_argument("--type", choices=["public","private"], required=True); a.set_defaults(func=add_subnet)
    sd = sub.add_parser("delete-subnet"); sd.add_argument("--vpc", required=True); sd.add_argument("--name", required=True); sd.set_defaults(func=delete_subnet)
    d = sub.add_parser("delete-vpc"); d.add_argument("--name", required=True); d.set_defaults(func=delete_vpc)
    pp = sub.add_parser("peer"); pp.add_argument("--vpc-a", required=True); pp.add_argument("--vpc-b", required=True); pp.add_argument("--allowed-cidrs", required=False, default=""); pp.set_defaults(func=peer_vpcs)
    un = sub.add_parser("unpeer"); un.add_argument("--vpc-a", required=True); un.add_argument("--vpc-b", required=True); un.set_defaults(func=unpeer_vpcs)
    l = sub.add_parser("list"); l.set_defaults(func=list_vpcs)

    return p

def main():
    if os.geteuid() != 0:
        log.error("Run as root."); sys.exit(1)
    parser = build_parser(); args = parser.parse_args()
    if not hasattr(args, "func"): parser.print_help(); sys.exit(0)
    ensure_ip_forwarding()
    try: args.func(args)
    except subprocess.CalledProcessError as e:
        log.exception(f"Command failed: {e}"); sys.exit(1)

if __name__ == "__main__":
    main()
