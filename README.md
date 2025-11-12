# Linux VPC Demo — Step-by-step Guide

This guide walks us through the manual verification of the VPC project (Parts 1–5) before we run the Makefile automation. Follow the steps in order. 
Each section contains the commands to run, what to expect, and troubleshooting notes.
Read more about building you own vpc on linux on my blog post here: 
Video demonstation lnk: 


## Prerequisites

- A Linux host (tested on Ubuntu). Run as root (use sudo where shown).

- iproute2, iptables, bridge-utils (or ip is sufficient). Example install on Debian/Ubuntu:

```
sudo apt update
sudo apt install -y iproute2 iptables iproute2
```

- Change permission for the create vpcctl.py script which we would use to run our vpc creation and subnet namespace, veth, and so on.

```
sudo chmod +x /usr/local/bin/vpcctl.py
```

- Ensure the host has an outbound interface (e.g. enp0s3, eth0). Note the name with:

```
ip route get 1.1.1.1 | awk '{print $5; exit}'
```
<img width="610" height="181" alt="Screenshot 2025-11-12 at 12 30 04" src="https://github.com/user-attachments/assets/4d1903ce-ecbe-4ed4-bdd0-6276a16b2575" />

Set environment variables used below accordingly.

## Setting Up Environment Variables File

Before starting, we need to create a variable file to store our project configuration. This allows us to quickly load environment variables for every session.

- Create a file called vars.sh in your project directory:

```
cat > vars.sh <<'EOF'
VPC_A=demo
VPC_B=demo-b
CIDR_A=10.50.0.0/16
CIDR_B=10.60.0.0/16
PUB_A=10.50.1.0/24
PRV_A=10.50.2.0/24
PUB_B=10.60.1.0/24
PRV_B=10.60.2.0/24
INET_IF=enp0s9 # Replace with your host network interface name
EOF
```
- Load it before you start any task:

```
source vars.sh
```

- You can confirm variables are set correctly using:

```
echo $VPC_A $VPC_B $INET_IF
```
<img width="623" height="255" alt="Screenshot 2025-11-12 at 12 38 26" src="https://github.com/user-attachments/assets/f70177a2-8858-40ad-9b43-3c66d11ce8a2" />

## **Task 1 — Core VPC Creation (manual)**

Step 1 – Create VPC A

Run:

```
sudo ./vpcctl.py create-vpc --name $VPC_A --cidr $CIDR_A --internet-interface $INET_IF
```
<img width="843" height="121" alt="Screenshot 2025-11-12 at 12 43 45" src="https://github.com/user-attachments/assets/71bfdb15-feee-415f-a72f-06614f815403" />

Then verify:

```
ip link show br-$VPC_A
sudo cat /var/lib/vpcctl/$VPC_A.json
```
<img width="921" height="167" alt="Screenshot 2025-11-12 at 12 45 57" src="https://github.com/user-attachments/assets/53448d90-2d8c-4ea9-9ef8-9365a03ce9b9" />

<img width="944" height="92" alt="Screenshot 2025-11-12 at 12 44 00" src="https://github.com/user-attachments/assets/67a833aa-e297-4bd5-a6c9-d7cd45784e2d" />

Step 2 – Add Public Subnet to VPC A

Run:

```
sudo ./vpcctl.py add-subnet --vpc $VPC_A --name public --cidr $PUB_A --type public
```

Veriify:

```
ip netns list
sudo ip netns exec ns-$VPC_A-public ip addr
sudo ip netns exec ns-$VPC_A-public ip route
```

<img width="767" height="347" alt="Screenshot 2025-11-12 at 12 47 39" src="https://github.com/user-attachments/assets/3971b9a7-1b4d-4a2e-885b-8869a3f5aa84" />

Step 3 – Add Private Subnet to VPC A

```
sudo ./vpcctl.py add-subnet --vpc $VPC_A --name private --cidr $PRV_A --type private
```

Verify:

```
sudo ip netns exec ns-$VPC_A-private ip addr
sudo ip netns exec ns-$VPC_A-private ip route
```

<img width="756" height="364" alt="Screenshot 2025-11-12 at 12 49 32" src="https://github.com/user-attachments/assets/1154b31a-75a0-425a-ba8f-d1d26db8f0b3" />

Step 4 – Test Intra-VPC Communication

Check connectivity within the same VPC (using bridge as router):

```
sudo ip netns exec ns-$VPC_A-public ping -c 3 10.50.2.10
sudo ip netns exec ns-$VPC_A-private ping -c 3 10.50.1.10
```
<img width="977" height="605" alt="Screenshot 2025-11-12 at 12 51 11" src="https://github.com/user-attachments/assets/c1374c2a-a633-43da-ac7c-71b82b3db6c9" />

