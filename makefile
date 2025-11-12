# ---------------------------
# Linux Self-Managed VPC Demo – Full Automation
# ---------------------------

# --- Variables ---
VPC_A       := demo
VPC_B       := demo-b
CIDR_A      := 10.50.0.0/16
CIDR_B      := 10.60.0.0/16
PUB_A       := 10.50.1.0/24
PRV_A       := 10.50.2.0/24
PUB_B       := 10.60.1.0/24
PRV_B       := 10.60.2.0/24
INET_IFACE  := enp0s3
POLICY_FILE := policy_public.json

# --- Core lifecycle ---
create:
	@echo "\n🧩 Creating VPC A ($(VPC_A))..."
	sudo ./vpcctl.py create-vpc --name $(VPC_A) --cidr $(CIDR_A) --internet-interface $(INET_IFACE)
	sudo ./vpcctl.py add-subnet --vpc $(VPC_A) --name public  --cidr $(PUB_A) --type public
	sudo ./vpcctl.py add-subnet --vpc $(VPC_A) --name private --cidr $(PRV_A) --type private
	@echo "\n🧩 Creating VPC B ($(VPC_B))..."
	sudo ./vpcctl.py create-vpc --name $(VPC_B) --cidr $(CIDR_B) --internet-interface $(INET_IFACE)
	sudo ./vpcctl.py add-subnet --vpc $(VPC_B) --name public  --cidr $(PUB_B) --type public
	sudo ./vpcctl.py add-subnet --vpc $(VPC_B) --name private --cidr $(PRV_B) --type private
	@echo "\n✅ Both VPCs created successfully.\n"

list:
	sudo ./vpcctl.py list

# --- Firewall ---
policy:
	sudo ./vpcctl.py apply-policy --policy $(POLICY_FILE)

# --- Simple web apps in each VPC public subnet ---
deploy-apps:
	@echo "\n🚀 Starting web apps in both public subnets..."
	-sudo pkill -f "http.server" || true
	sudo ip netns exec ns-$(VPC_A)-public python3 -m http.server 80 &
	sudo ip netns exec ns-$(VPC_B)-public python3 -m http.server 80 &
	sleep 2
	curl -I http://10.50.1.10 || true
	curl -I http://10.60.1.10 || true
	@echo "\n✅ Web servers deployed on both VPCs.\n"

# --- Peering between VPC A and VPC B ---
peer:
	@echo "\n🔗 Establishing peering between $(VPC_A) and $(VPC_B)..."
	sudo ./vpcctl.py peer --vpc-a $(VPC_A) --vpc-b $(VPC_B) --allowed-cidrs $(CIDR_A),$(CIDR_B)
	@echo "\n✅ Peering established.\n"

unpeer:
	sudo ./vpcctl.py unpeer --vpc-a $(VPC_A) --vpc-b $(VPC_B)
	@echo "\n✅ Peering removed.\n"

# --- Test connectivity (intra- and inter-VPC) ---
test:
	@echo "\n🧪 Testing intra-VPC connectivity..."
	sudo ip netns exec ns-$(VPC_A)-public ping -c 2 10.50.2.10 || true
	sudo ip netns exec ns-$(VPC_B)-public ping -c 2 10.60.2.10 || true
	@echo "\n🧪 Testing inter-VPC connectivity..."
	sudo ip netns exec ns-$(VPC_A)-public ping -c 2 10.60.1.10 || true
	sudo ip netns exec ns-$(VPC_B)-public ping -c 2 10.50.1.10 || true
	@echo "\n🌐 Testing HTTP access across peers..."
	curl -I http://10.50.1.10 || true
	curl -I http://10.60.1.10 || true
	@echo "\n✅ Connectivity tests completed.\n"

# --- Cleanup & rebuild ---
cleanup:
	@echo "\n🧹 Cleaning up all VPC resources..."
	sudo ./vpcctl.py delete-vpc --name $(VPC_A) || true
	sudo ./vpcctl.py delete-vpc --name $(VPC_B) || true
	@echo "\n✅ Cleanup complete.\n"

recreate: cleanup create list
	@echo "\n♻️  Recreated both VPCs successfully.\n"

status:
	ip netns list
	bridge link show | grep br- || true
	sudo iptables -t nat -L POSTROUTING -n -v | grep 10. || true

.PHONY: create list policy deploy-apps peer unpeer test cleanup recreate status
