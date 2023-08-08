# Mod 3 Exercise Notes
---

## 3-1-2
---
![Alt text](image/ex3-2map1.png)

Question 1  
Does Workgroup 1 have access to the Web Server (www in DMZ)?  
Yes!  

Question 2  
Does the Web Server in the DMZ have access to Workgroup 1?  
No!  

Question 3  
What is the purpose of Firewall B?  
To block all inbound traffic except for ports used by www, db, and email

Question 4  
What is the purpose of Firewall D?  
To block all inbound traffic  

Question 5  
A coworker in Workgroup 3 needs to send out an email to a coworker in Workgroup 1. What is the correct series of traffic network devices for this email to be sent and then received by the coworker?  
H, G, E, D, A, B, C, C, B, A, D, E, G

![Alt text](image/ex3-2map2.png)

Question 6  
You are in Workgroup 1 and the following actions occur:

You connect to your internal SharePoint and download a document.
You email it to a coworker in Workgroup 2. (Assume coworker pulled email)
Your coworker proceeds to upload it to the webserver.

Follow the path of the network traffic that was created and count the number of hops. What is the total number of hops? (Hops include routers and endpoints.)

13 hops  

Question 7  
Does Workgroup 2 have access to Workgroup 3?  
Yes, the VPN connection between D and C allows access to Workgroup 3.  

Question 8  
Workgroup 1 and 2 want to create an FTP server and a database that both are allowed to access but would not allow access to Workgroup 3.  

What would be the best way to accomplish this?
Connect a firewall internal to G, connect a switch to that firewall, and connect the FTP server and database to the switch. (As the VPN connection would be coming inbound the firewall could block all inbound VPN traffic)  

Question 9   
By analyzing web traffic at Routers A and B, it is discovered that ransomware was attempted to be delivered by exploiting a vulnerability in version 1.0.2.8 Firewall OS. Firewall C had not been updated before the attack, but Firewall D was updated. Using the provided diagram, determine what workgroups could be affected by the attack.  
Only Workgroup 3 could be affected because the firewall D was updated.  

Question 10  
A Workgroup 1 user is downloading a file from Workgroup 3 with no issue, however, a user from Workgroup 3 is unable to download a file from Workgroup 1. Workgroup 1 is also not able to access the internet. What is most likely the issue?  
Workgroup 1 switch is misconfigured.


## 3-1-3 Develop Sensor Strategy - Placement of Sensors  
---
[Basic Network Device Logging](https://www.networkcomputing.com/networking/network-device-management-part-1-snmp-logging)  
[Learn about Netflow from Cisco Documentation](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-netflow/index.html)  
[Network Traffic Logging](https://sansorg.egnyte.com/dl/v8yKo67ANC)  
[IDS and IPS deployment strategies](https://sansorg.egnyte.com/dl/pRVtSe53cF)  


Question 1  
What hardware device typically will NOT generate network logs?  
Hub

Question 2  
What type of data is usually NOT contained in a network log?  
Message content  

Question 3  
All communications from one network to another must travel through _________?  
a router  

Question 4  
An IDS analyzes traffic by comparing it with known _____________.  
event signatures  

Question 5  
What type of data is NOT captured in NetFlow monitoring?  
Packet payload  

Question 6  
A network tap will send a copy of a packet of data to the monitoring system but also will allow the packet to be sent to its destination.  
True  

Question 7  
Configuring a NIC to capture packets in promiscuous mode allows Wireshark to capture ____________.  
all packets it discovers, even if NOT addressed to the NIC  

Question 8  
Which combination of technologies is used to allow systems with private network addresses to communicate on the internet?  
PAT and NAT  

Question 9  
Which item listed below maintains a pool of IP addresses and automatically assigns an address to a machine when one is requested?  
DHCP  

Question 10  
Which issue must be addressed when planning to implement a physical tap?  
The installation of the tap will require a temporary break in the network connection.  




![Alt text](image/ex3-3map1.png)

Question 11
As the packet travels from Computer A to Computer B, what is the packet's source MAC address within Network 1?  
11:3D:35:99:43:FD  

Question 12  
As the packet travels from Computer A to Computer B, what is the destination MAC address as the packet leaves Router X?  
11:3D:35:99:43:FD  

Question 13  
As the packet travels from Computer A to Computer B, what is the source IP address as the packet leaves Router X?  
4.2.2.50  

Question 14  
As the packet travels from Computer A to Computer B, what is the destination IP address on the packet?  
32.54.1.21  

Question 15  
As the packet travels from Computer A to Computer B, what is the source MAC address on the packet after the packet has traversed Network 2 (while still inside Network 2)?  
00:00:01:55:3d:3f  
(need clarification on this - why does it change?)  

Question 16  
As the packet travels from Computer A to Computer B, what is the packet's destination MAC address after the packet traverses Network 2 (while still inside Network 2)?  
00:2b:11:32:FA:34  

Question 17  
As the packet travels from Computer A to Computer B, what is the source IP address on the packet when the packet is traversing Network 2?  
4.2.2.50  

Question 18  
As the packet travels from Computer A to Computer B, what is the destination IP address on the packet as it traverses Network 2?  
32.54.1.21  

Question 19  
As the packet travels from Computer A to Computer B, what is the source MAC address for the packet as it traverses Network 3?  
00:2b:11:32:43:23  

Question 20  
As the packet travels from Computer A to Computer B, what is the destination MAC address for the packet as it traverses Network 3?  
01:00:20:3F:FF:3D  

Question 21  
As the packet travels from Computer A to Computer B, what is the source IP address for the packet as it traverses Network 3?
4.2.2.50  

Question 22  
As the packet travels from Computer A to Computer B, what is the destination IP address for the packet as it traverses Network 3?  
32.54.1.21  


![Alt text](image/ex3-3map2.png)

Question 23  
If a packet was traveling from Computer C to Computer B, what is the source IP address that Sniffer 2 will see?  
192.168.100.153  

Question 24  
If a packet was traveling from Computer C to Computer B, what destination IP address will be seen by Sniffer 2?  
20.1.23.5  

Question 25  
If a packet was traveling from Computer C to Computer B, what source IP address will be seen by Sniffer 1?  
192.168.100.153  

Question 26  
If a packet was traveling from Computer C to Computer B, what destination IP address will be seen by Sniffer 1?  
20.1.23.5  

Question 27  
If a packet was traveling from Computer A to Computer D, what source IP address will be seen by Sniffer 1?  
4.3.2.4  

Question 28  
If a packet was traveling from Computer A to Computer D, what destination IP address will be seen by Sniffer 1?  
66.94.234.13  

Question 29  
If a packet was traveling from Computer A to Computer D, what source IP address will be seen by Sniffer 3?  
4.3.2.4  

Question 30  
If a packet was traveling from Computer A to Computer D, what destination IP address will be seen by Sniffer 3?  
172.16.1.5  

![Alt text](image/ex3-3dev1.png)  
![Alt text](image/ex3-3map3.png)  

### Scenario 1  
---
An internal workstation was identified as having accessed unauthorized documents on an internal file server on the network. The customer wants to monitor the workstation for anymore unauthorized activity.  

IP Address: 192.168.100.34  

MAC Address: 00:01:33:FA:B1:03  

Question 31  
List the possible locations for sensor placement and the problems or considerations at each location.  
Router 1 - Will see all traffic  
Switch 4 - will only monitor the servers  
switch 2 - will monitor all workstations  
 
Question 32  
Which filter would you place on the sniffer, an IP address or a MAC address? Why?  
IP address. Less volatile/not in flux  

Question 33  
Which ports/protocols would you use?  
Monitor for SMB/FTP

Question 34  
Based on what is provided, what other questions would you ask the network engineer or the system administrator?


### Scenario 2  
---
The customer has reported that their website has been defaced with anti-government material. The website is hosted on a server that is connected to the DMZ segment of the firewall. Reviewing the IIS logs, there are suspicious web requests from the IP address 214.3.152.67. It is suspected that the defacement came from that IP address. You are in charge of collecting data from the sensors and must decide from which sensors to collect data. Use the document and map provided to answer the following questions.  

Question 35  
What are the possible in-line sensors that you can collect data of value from that is related to the defacement?  
Firewall01 may have logs relating to the incident  

Question 36  
Are there any other sensors of interest? Why?  
No, there are no other sensors  

Question 37  
What additional questions would you ask the network engineer or system administrator?  


### Scenario 3
---
The customer states that a person is using a workstation on Switch 01 and is performing suspicious actions against the Victim Server on Switch 04.  

![Alt text](image/ex3-3map4.png)  

Question 38  
Using the local organic sensors, why is Switch 01 the best placement option?  
If the customer believes the suspicious activity is from Switch 01, tapping here will allow us to receive all traffic from the suspicious hosts.  

Question 39  
If it is determined that the subject has access to a remote VPN account, how does this change the answer for the best placement?  
If the malicious actor has remote access, tapping at Switch01 will no longer allow us to see the relevant traffic.

### Scenario 4
---
The subject is now an unknown attacker coming from the Internet. The arrow pointing to the firewall indicating a bad location is placed in both examples to emphasize that a CPT member should never try to place a network monitor directly into any firewall or router. In this example, both Switch 05 and Switch 03 are good locations to place a monitor.   
![Alt text](image/ex3-3map5.png)  

Question 40   
Why would Switch 05 be a better location to monitor than Switch 03? What could be some benefits of monitoring Switch 03?  
Switch05 will allow us to view all traffic coming into the network from the internet. A benefit of Switch03 is that the traffic will be a more narrow scope allowing us to fixate specifically on the traffic to the servers.  

### Scenario 5
---
