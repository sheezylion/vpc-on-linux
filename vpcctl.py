#!/usr/bin/env python3

"""
vpcctl.py – Lightweight Linux VPC simulator with automatic bridge isolation

Features:
 - create-vpc / add-subnet / delete-vpc / peer / unpeer / apply-policy
 - Automatic iptables & bridge-netfilter setup for isolation
 - NAT gateway for public subnets
 - JSON-based firewall policies inside namespaces
"""

import argparse, json, logging, os, shlex, subprocess, sys, hashlib

# ---------- logging ----------
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger("vpcctl")

# ---------- helpers ----------
def run_cmd(cmd, check=True, capture=False):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    log.debug("RUN: %s", " ".join(cmd))
    if capture:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return r
    return subprocess.run(cmd, check=check)

def exists_ip_link(name):
    return subprocess.run(["ip", "link", "show", name],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def list_netns():
    r = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]

def exists_netns(name):
    return name in list_netns()

# ---------- system prep ----------
def ensure_bridge_netfilter():
    subprocess.run(["modprobe", "br_netfilter"], check=False)
    subprocess.run(["sysctl", "-w", "net.bridge.bridge-nf-call-iptables=1"], check=False)
    subprocess.run(["sysctl", "-w", "net.bridge.bridge-nf-call-ip6tables=1"], check=False)
    log.info("Bridge netfilter enabled (br_netfilter + iptables filtering on bridges)")

def ensure_ip_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    ensure_bridge_netfilter()
    log.info("IP forwarding and bridge filtering active")

def enforce_bridge_isolation():
    """Drop all inter-bridge traffic by default"""
    run_cmd(["iptables", "-C", "FORWARD", "-i", "br-*", "-o", "br-*", "-j", "DROP"], check=False)
    run_cmd(["iptables", "-A", "FORWARD", "-i", "br-*", "-o", "br-*", "-j", "DROP"], check=False)
    log.info("Default inter-bridge isolation rule enforced")

# ---------- naming ----------
def short_hash(s, n=3): return hashlib.md5(s.encode()).hexdigest()[:n]
def br_name(vpc): return f"br-{vpc}"
def ns_name(vpc, subnet): return f"ns-{vpc}-{subnet}"
def veth_host_name(vpc, subnet): return f"veth-{short_hash(vpc+subnet)}-h"
def veth_ns_name(vpc, subnet): return f"veth-{short_hash(vpc+subnet)}-n"
def peer_ifname(a,b,side): return f"pr-{a[:3]}-{b[:3]}-{side}"

# ---------- metadata ----------
META_DIR="/var/lib/vpcctl"; os.makedirs(META_DIR, exist_ok=True)
def meta_file_for(vpc): return os.path.join(META_DIR, f"{vpc}.json")
def save_meta(vpc,m): open(meta_file_for(vpc),"w").write(json.dumps(m))
def load_meta(vpc):
    p=meta_file_for(vpc)
    return json.load(open(p)) if os.path.exists(p) else None

# ---------- VPC CRUD ----------
def create_vpc(args):
    vpc, cidr, inet = args.name, args.cidr, args.internet_interface
    bridge = br_name(vpc)
    ensure_ip_forwarding()
    enforce_bridge_isolation()

    log.info(f"Creating VPC {vpc} CIDR={cidr} IF={inet}")
    if not exists_ip_link(bridge):
        run_cmd(["ip","link","add","name",bridge,"type","bridge"],check=False)
        run_cmd(["ip","link","set",bridge,"up"],check=False)
    meta={"name":vpc,"cidr":cidr,"internet_interface":inet,"subnets":{}}
    save_meta(vpc,meta)
    log.info("Saved metadata for %s", vpc)

def add_subnet(args):
    vpc,name,cidr,stype=args.vpc,args.name,args.cidr,args.type.lower()
    bridge=br_name(vpc)
    meta=load_meta(vpc) or sys.exit("Create VPC first")

    ns=ns_name(vpc,name)
    veth_h,veth_n=veth_host_name(vpc,name),veth_ns_name(vpc,name)
    if not exists_netns(ns):
        run_cmd(["ip","netns","add",ns],check=False)
    if not exists_ip_link(veth_h):
        run_cmd(["ip","link","add",veth_h,"type","veth","peer","name",veth_n],check=False)
    run_cmd(["ip","link","set",veth_h,"master",bridge],check=False)
    run_cmd(["ip","link","set",veth_h,"up"],check=False)
    run_cmd(["ip","link","set",veth_n,"netns",ns],check=False)
    run_cmd(["ip","netns","exec",ns,"ip","link","set","dev",veth_n,"name","eth0"],check=False)
    run_cmd(["ip","netns","exec",ns,"ip","link","set","eth0","up"],check=False)

    base,prefix=cidr.split("/"); o=base.split(".")
    gw=f"{o[0]}.{o[1]}.{o[2]}.1/{prefix}"
    host=f"{o[0]}.{o[1]}.{o[2]}.10/{prefix}"
    gw_ip=gw.split("/")[0]
    r=run_cmd(["ip","addr","show","dev",bridge],capture=True)
    if gw_ip not in r.stdout:
        run_cmd(["ip","addr","add",gw,"dev",bridge],check=False)
    run_cmd(["ip","netns","exec",ns,"ip","addr","add",host,"dev","eth0"],check=False)
    run_cmd(["ip","netns","exec",ns,"ip","route","add","default","via",gw_ip],check=False)

    meta["subnets"][name]={"cidr":cidr,"type":stype}
    save_meta(vpc,meta)
    if stype=="public":
        internet_if=meta.get("internet_interface")
        if internet_if: add_nat_for_subnet(internet_if,cidr,bridge)

def add_nat_for_subnet(inet_if,subnet,bridge):
    run_cmd(["iptables","-t","nat","-A","POSTROUTING","-s",subnet,"-o",inet_if,"-j","MASQUERADE"],check=False)
    run_cmd(["iptables","-A","FORWARD","-i",bridge,"-o",inet_if,"-j","ACCEPT"],check=False)
    run_cmd(["iptables","-A","FORWARD","-i",inet_if,"-o",bridge,"-m","state","--state","RELATED,ESTABLISHED","-j","ACCEPT"],check=False)
    log.info("NAT configured for %s -> %s",subnet,inet_if)

def delete_vpc(args):
    vpc = args.name
    bridge = br_name(vpc)
    log.info("Deleting VPC '%s'", vpc)

    meta = load_meta(vpc) or {"subnets": {}}

    # --- Delete all subnets (namespaces and veths)
    for s in list(meta["subnets"].keys()):
        try:
            delete_subnet(argparse.Namespace(vpc=vpc, name=s))
        except Exception as e:
            log.warning("Error deleting subnet %s: %s", s, e)

    # --- Delete the bridge
    if exists_ip_link(bridge):
        run_cmd(["ip", "link", "set", bridge, "down"], check=False)
        run_cmd(["ip", "link", "delete", bridge, "type", "bridge"], check=False)
        log.info("Deleted bridge %s", bridge)
    else:
        log.info("Bridge %s not found (already removed)", bridge)

    # --- Remove metadata
    mf = meta_file_for(vpc)
    if os.path.exists(mf):
        try:
            os.remove(mf)
            log.info("Removed metadata %s", mf)
        except Exception as e:
            log.warning("Could not remove metadata: %s", e)

    # --- Delete any orphaned namespaces
    for ns in list_netns():
        if ns.startswith(f"ns-{vpc}-"):
            run_cmd(["ip", "netns", "delete", ns], check=False)
            log.info("Deleted namespace %s", ns)

    # --- Clean up stale namespace mounts in /run/netns/
    netns_dir = "/run/netns"
    if os.path.exists(netns_dir):
        for fname in os.listdir(netns_dir):
            if fname.startswith(f"ns-{vpc}-"):
                full_path = os.path.join(netns_dir, fname)
                try:
                    subprocess.run(["umount", full_path], check=False)
                    os.remove(full_path)
                    log.info("Unmounted and removed stale namespace handle: %s", full_path)
                except Exception as e:
                    log.warning("Could not remove namespace handle %s: %s", full_path, e)

    log.info("VPC '%s' fully deleted and cleaned.", vpc)



# ---------- peering ----------
def peer_vpcs(args):
    a,b=args.vpc_a,args.vpc_b
    allowed=[c.strip() for c in args.allowed_cidrs.split(',') if c.strip()]
    br_a,br_b=br_name(a),br_name(b)
    if_a,if_b=peer_ifname(a,b,'a'),peer_ifname(a,b,'b')
    if not exists_ip_link(if_a):
        run_cmd(["ip","link","add",if_a,"type","veth","peer","name",if_b],check=False)
    run_cmd(["ip","link","set",if_a,"master",br_a],check=False)
    run_cmd(["ip","link","set",if_b,"master",br_b],check=False)
    run_cmd(["ip","link","set",if_a,"up"],check=False)
    run_cmd(["ip","link","set",if_b,"up"],check=False)
    for cidr in allowed:
        run_cmd(["ip","route","replace",cidr,"dev",if_a],check=False)
        run_cmd(["ip","route","replace",cidr,"dev",if_b],check=False)
    log.info("Peering between %s <-> %s active (CIDRs %s)",a,b,allowed)

def unpeer_vpcs(args):
    a,b=args.vpc_a,args.vpc_b
    for ifn in [peer_ifname(a,b,'a'),peer_ifname(a,b,'b')]:
        if exists_ip_link(ifn): run_cmd(["ip","link","delete",ifn],check=False)
    log.info("Peering removed between %s and %s",a,b)

# ---------- policy ----------
def apply_policy(args):
    pf=args.policy
    if not os.path.exists(pf): sys.exit(f"Policy file {pf} not found")
    policy=json.load(open(pf))
    subnet=policy.get("subnet") or sys.exit("Missing subnet in policy")
    ns=None
    for fn in os.listdir(META_DIR):
        if fn.endswith(".json"):
            meta=json.load(open(os.path.join(META_DIR,fn)))
            for sname,sdata in meta.get("subnets",{}).items():
                if sdata.get("cidr")==subnet: ns=ns_name(meta["name"],sname)
    if not ns: sys.exit("Subnet not found for policy")
    run_cmd(f"ip netns exec {ns} iptables -F",check=False)
    run_cmd(f"ip netns exec {ns} iptables -P INPUT DROP",check=False)
    run_cmd(f"ip netns exec {ns} iptables -A INPUT -i lo -j ACCEPT",check=False)
    run_cmd(f"ip netns exec {ns} iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",check=False)
    for r in policy.get("ingress",[]):
        port=r.get("port"); proto=r.get("protocol","tcp"); act=r.get("action","allow").lower()
        port_args=[] if str(port).lower()=="any" else ["--dport",str(port)]
        jump="ACCEPT" if act=="allow" else "DROP"
        run_cmd(["ip","netns","exec",ns,"iptables","-A","INPUT","-p",proto]+port_args+["-j",jump],check=False)
    log.info("Policy applied inside %s",ns)

# ---------- CLI ----------
def build_parser():
    p=argparse.ArgumentParser(prog='vpcctl')
    sub=p.add_subparsers(dest='cmd')
    c=sub.add_parser('create-vpc'); c.add_argument('--name',required=True); c.add_argument('--cidr',required=True); c.add_argument('--internet-interface',required=True); c.set_defaults(func=create_vpc)
    a=sub.add_parser('add-subnet'); a.add_argument('--vpc',required=True); a.add_argument('--name',required=True); a.add_argument('--cidr',required=True); a.add_argument('--type',choices=['public','private'],required=True); a.set_defaults(func=add_subnet)
    d=sub.add_parser('delete-vpc'); d.add_argument('--name',required=True); d.set_defaults(func=delete_vpc)
    ppol=sub.add_parser('apply-policy'); ppol.add_argument('--policy',required=True); ppol.set_defaults(func=apply_policy)
    pp=sub.add_parser('peer'); pp.add_argument('--vpc-a',required=True); pp.add_argument('--vpc-b',required=True); pp.add_argument('--allowed-cidrs',default=''); pp.set_defaults(func=peer_vpcs)
    un=sub.add_parser('unpeer'); un.add_argument('--vpc-a',required=True); un.add_argument('--vpc-b',required=True); un.set_defaults(func=unpeer_vpcs)
    return p

def main():
    if os.geteuid()!=0: sys.exit("Run as root")
    args=build_parser().parse_args()
    if not hasattr(args,"func"): return print("See --help")
    try: args.func(args)
    except subprocess.CalledProcessError as e:
        log.error("Command failed: %s", e)

if __name__=="__main__": main()

