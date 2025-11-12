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

### Step 1 – Create VPC A

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

### Step 2 – Add Public Subnet to VPC A

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

### Step 3 – Add Private Subnet to VPC A

```
sudo ./vpcctl.py add-subnet --vpc $VPC_A --name private --cidr $PRV_A --type private
```

Verify:

```
sudo ip netns exec ns-$VPC_A-private ip addr
sudo ip netns exec ns-$VPC_A-private ip route
```

<img width="756" height="364" alt="Screenshot 2025-11-12 at 12 49 32" src="https://github.com/user-attachments/assets/1154b31a-75a0-425a-ba8f-d1d26db8f0b3" />

### Step 4 – Test Intra-VPC Communication

Check connectivity within the same VPC (using bridge as router):

```
sudo ip netns exec ns-$VPC_A-public ping -c 3 10.50.2.10
sudo ip netns exec ns-$VPC_A-private ping -c 3 10.50.1.10
```
<img width="977" height="605" alt="Screenshot 2025-11-12 at 12 51 11" src="https://github.com/user-attachments/assets/c1374c2a-a633-43da-ac7c-71b82b3db6c9" />

## **Task 1 — Core VPC Creation (manual)**

### Step 1 — Check NAT Configuration

List your NAT and forwarding rules:

```
sudo iptables -t nat -L POSTROUTING -n -v | grep 10.50
sudo iptables -L FORWARD -n -v | grep br-$VPC_A
```


You should see MASQUERADE rules for our public subnet and ACCEPT rules between the bridge and our internet interface.

<img width="1105" height="234" alt="Screenshot 2025-11-12 at 12 56 31" src="https://github.com/user-attachments/assets/21e32c35-b904-4985-808a-63e257834080" />


### Step 2 — Verify Outbound Internet from Public Namespace

Test from the public subnet namespace:

```
sudo ip netns exec ns-$VPC_A-public ping -c 3 8.8.8.8
```

Expected: It should reach the internet (assuming your host has internet access).

<img width="921" height="312" alt="Screenshot 2025-11-12 at 12 57 54" src="https://github.com/user-attachments/assets/55c93eba-acce-4f8c-b5f3-e0c4476b87ac" />


### Step 3 — Verify Private Namespace Has No Internet

From the private namespace:

```
sudo ip netns exec ns-$VPC_A-private ping -c 3 8.8.8.8
```

Expected: Should fail — private subnet has no NAT access.

<img width="866" height="331" alt="Screenshot 2025-11-12 at 12 58 54" src="https://github.com/user-attachments/assets/6eb16ad2-0f92-46d3-a206-79113c32d1a1" />


### App Deployment Test

- Deploy app in public subnet

Run:

```
sudo ip netns exec ns-$VPC_A-public python3 -m http.server 80 &
```


Then test from your host:

```
curl -I http://10.50.1.10
```

Expected:

You should get a 200 OK or HTTP/1.0 200 OK response — this confirms that the host and public subnet can communicate (simulating “internet-facing” behavior).

<img width="1557" height="621" alt="Screenshot 2025-11-12 at 13 04 58" src="https://github.com/user-attachments/assets/4137128a-3ec9-417f-85ee-7648b467acb5" />

- Deploy app in private subnet

Run:

```
sudo ip netns exec ns-$VPC_A-private python3 -m http.server 80 &
```


Then test again from your host:

```
curl -I http://10.50.2.10
```

Expected:

Expected: reachable by default (bridge exposure). This is normal behavior in Linux since the host shares the bridge.

**Simulate True Private Subnet Isolation**

To make the private subnet unreachable from the host (more realistic private behavior), apply these iptables rules:

```
sudo iptables -A FORWARD -i br-$VPC_A -d $PRV_A -j DROP
sudo iptables -A INPUT -s $PRV_A -j DROP
```
Lets test again:

```
curl -I http://10.50.2.10
```
Expected: Timeout or connection refused.

This ensures the host cannot directly access private subnet namespaces while maintaining internal communication between subnets.

<img width="716" height="221" alt="Screenshot 2025-11-12 at 13 10 50" src="https://github.com/user-attachments/assets/b4b9c21b-10b8-47bc-a772-f5486754d6c6" />



## **Task 3 — VPC Isolation & Peering**

### Step 1 — Create VPC B

Since we already sourced our variables (source vars.sh), just run:

```
sudo ./vpcctl.py create-vpc --name $VPC_B --cidr $CIDR_B --internet-interface $INET_IF
sudo ./vpcctl.py add-subnet --vpc $VPC_B --name public  --cidr $PUB_B --type public
sudo ./vpcctl.py add-subnet --vpc $VPC_B --name private --cidr $PRV_B --type private
```
Expected results:

- New bridge br-demo-b created.

- Namespaces: ns-demo-b-public and ns-demo-b-private.

IPs assigned:

- 10.60.1.10 (public)

- 10.60.2.10 (private)

- Gateway on bridge 10.60.1.1 and 10.60.2.1.

<img width="1191" height="416" alt="Screenshot 2025-11-12 at 13 20 11" src="https://github.com/user-attachments/assets/a6ed7d55-ccee-463f-9cfb-514c36157602" />

### Step 2 — Verify Isolation (No Peering Yet)

Ping from VPC A to VPC B:

```
sudo ip netns exec ns-$VPC_A-public ping -c 3 10.60.1.10 || true
```


and from VPC B to VPC A:

```
sudo ip netns exec ns-$VPC_B-public ping -c 3 10.50.1.10 || true
```

Expected: No response (isolation works).
This confirms the bridge-to-bridge drop rule is active.

<img width="937" height="483" alt="Screenshot 2025-11-12 at 13 22 34" src="https://github.com/user-attachments/assets/ae26342c-0c4a-43f8-8db1-347d6e7241c0" />

### Step 3 — Create Peering Between VPC A and VPC B

Now establish explicit connectivity:

```
sudo ./vpcctl.py peer --vpc-a $VPC_A --vpc-b $VPC_B --allowed-cidrs $CIDR_A,$CIDR_B
```


This creates a veth pair:

- One end connects to br-demo

- The other connects to br-demo-b

- Adds host routes for both CIDRs

Check interfaces:

```
ip link show | grep pr-
```
You should see something like:

- pr-dem-dem-b-a
- pr-dem-dem-b-b

<img width="1115" height="418" alt="Screenshot 2025-11-12 at 13 34 02" src="https://github.com/user-attachments/assets/5ff2b25e-5dea-4222-b7f6-5116917bd164" />



### Step 4 — Verify Peering Works

Now lets repeat the same ping tests:

```
sudo ip netns exec ns-$VPC_A-public ping -c 3 10.60.1.10
sudo ip netns exec ns-$VPC_B-public ping -c 3 10.50.1.10
```

✅ Expected:
Both should succeed — this confirms your peering link is active and routes are properly in place.


