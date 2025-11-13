# Linux VPC Demo — Step-by-step Guide

This guide walks us through the manual verification of the VPC project (Parts 1–5) before we run the Makefile automation. Follow the steps in order. 
Each section contains the commands to run, what to expect, and troubleshooting notes.

Read more about building you own vpc on linux on my blog post here: https://medium.com/@seadesokan/building-a-vpc-virtual-private-cloud-on-a-linux-host-beginner-guide-98c19098ec49?postPublishedType=initial

Video demonstation lnk: https://www.loom.com/share/f3de180ddae2413c8cbbcc59b2b5c5e9


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

## **Task 2 — Routing and NAT gateway**

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

Expected:
Both should succeed — this confirms your peering link is active and routes are properly in place.


<img width="1150" height="497" alt="Screenshot 2025-11-12 at 14 10 31" src="https://github.com/user-attachments/assets/540c2524-3a04-44c4-b413-ebee6a7d097c" />


## **Task 4 — Firewall & Security Groups**

**Objective**

We Use a JSON file to define ingress rules for a subnet namespace (allow or deny ports/protocols), and apply them dynamically with your vpcctl.py apply-policy command.

### Step 1 — Create the policy file

Create a file named policy_public.json:

```
vim policy_public.json
```


Paste this:
```
{
  "subnet": "10.50.1.0/24",
  "ingress": [
    {"port": 80, "protocol": "tcp", "action": "allow"},
    {"port": 22, "protocol": "tcp", "action": "deny"}
  ]
}
```

Then save and exit 

This policy means:

- Allow HTTP (port 80)

- Deny SSH (port 22)

- Drop all other unsolicited inbound traffic by default

### Step 2 — Apply the firewall policy

Run:

```
sudo ./vpcctl.py apply-policy --policy policy_public.json
```

<img width="694" height="189" alt="Screenshot 2025-11-12 at 14 15 48" src="https://github.com/user-attachments/assets/d7ed26dc-9360-489d-a124-7bf50242103a" />

### Step 3 — Verify rules inside the namespace

You can confirm the rules were applied correctly:

```
sudo ip netns exec ns-demo-public iptables -L -n -v
```
<img width="1047" height="478" alt="Screenshot 2025-11-12 at 14 16 49" src="https://github.com/user-attachments/assets/3697de12-b8b2-4f3f-9943-e71db23a7924" />

### Step 4 — Test behavior

Start a simple web server in the public namespace:

```
sudo ip netns exec ns-demo-public python3 -m http.server 80 &
```

Then from your host, try both:

Port 80 (should succeed)

```
curl -I http://10.50.1.10
```
<img width="579" height="61" alt="Screenshot 2025-11-12 at 14 21 37" src="https://github.com/user-attachments/assets/56a43219-b0c0-41b2-bbf5-213a911b5692" />


❌ Port 22 (should fail)

```
nc -zv 10.50.1.10 22
```

## **Task 5 — Cleanup & Automation**

- Ensure full lifecycle management:

- Cleanly remove VPCs, namespaces, bridges, and routes.

- Verify idempotency (safe to rerun).

- Automate common tasks (create, list, peer, test, delete) in your Makefile.

### Step 1 — Validate delete-vpc cleanup

Run:

```
sudo ./vpcctl.py delete-vpc --name $VPC_A || true
sudo ./vpcctl.py delete-vpc --name $VPC_B || true
```

Confirm:

```
ip netns list
ip link show | grep br-
```
No ns-demo-* namespaces and no br-demo or br-demo-b bridges.

<img width="597" height="248" alt="Screenshot 2025-11-12 at 14 36 28" src="https://github.com/user-attachments/assets/1901bd70-3fa6-4991-88cb-32575c98f7a2" />


## **Makefile Automation**

Now let’s plug it all together.
We update our Makefile so it automates every major phase — creation, listing, policy, peering, testing, and cleanup.

### Step 1: Create both VPCs

Run:

```
make create
```

This will:

- Create VPC A (demo) and VPC B (demo-b)

- Add their public and private subnets

- Enable NAT for public subnets

- Log every step clearly

<img width="734" height="659" alt="Screenshot 2025-11-12 at 14 46 51" src="https://github.com/user-attachments/assets/64cbac73-4e8d-4a47-a4d7-f2f69842566a" />


Check progress:

```
ip netns list
ip link show | grep br-
p link show grep | veth
```

<img width="831" height="771" alt="Screenshot 2025-11-12 at 14 48 32" src="https://github.com/user-attachments/assets/be1481ca-9abb-41b5-b13b-b06307693398" />

### Step 2- Deploy apps (optional)

You can manually start demo HTTP servers inside each public subnet:

```
sudo ip netns exec ns-demo-public python3 -m http.server 80 &
sudo ip netns exec ns-demo-b-public python3 -m http.server 80 &
```

Then verify:

```
curl -I http://10.50.1.10
curl -I http://10.60.1.10
```

<img width="1447" height="286" alt="Screenshot 2025-11-12 at 14 50 33" src="https://github.com/user-attachments/assets/0fc227aa-f485-4712-a94d-b172b11c81ab" />

### Step 3 — Apply security policy

Apply your JSON-based firewall:

```
make policy
```

Check applied rules:

```
sudo ip netns exec ns-demo-public iptables -L -n -v
```

<img width="814" height="493" alt="Screenshot 2025-11-12 at 14 52 54" src="https://github.com/user-attachments/assets/0dd9d11a-5db0-4328-9dec-20f98001b1dc" />

### Step 4 — Peer both VPCs

Establish peering:

```
make peer
```

This links br-demo ↔ br-demo-b via veth and configures static routes for the allowed CIDRs.

Test inter-VPC reachability:

```
make test
```

Unpeer:

```
make unpeer
```
<img width="666" height="691" alt="Screenshot 2025-11-12 at 14 54 56" src="https://github.com/user-attachments/assets/c8b6627b-33aa-4551-be6a-155cbc0513ea" />

### Step 5 — Cleanup

To remove everything:

```
make cleanup
```

This automatically:

- Deletes namespaces and bridges

- Unmounts /run/netns handles

- Flushes iptables NAT/forward rules

- Removes metadata JSON

Expected End State When finished:

```
ip netns list       # no lingering namespaces
bridge link show    # no br-demo or br-demo-b
sudo iptables -L FORWARD -n -v | grep br-
# (empty)
```
<img width="747" height="953" alt="Screenshot 2025-11-12 at 14 58 11" src="https://github.com/user-attachments/assets/0e9b66a2-3145-4065-9ab7-d20a3f03376f" />

Environment is clean, reusable, and automation-ready.



