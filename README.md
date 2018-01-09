# SDNWirelessLinkCapacityEstimator
Wireless link capacity estimation using RYU contoller

## Start Controller: 
ryu-manager main.py (use "--verbose" option for additional debug)
## Start two switch topology: 
sudo mn topo=linear,2 --controller=remote 
## Check switch flow tables:
sudo ovs-ofctl dump-flows s1 (s1 switch id)
Note: please check topo using mininet command "net"

