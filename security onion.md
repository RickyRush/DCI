### Setting up Security Onion
---

There are two pieces to setting this up, the server and the sensor. First, we will configure the server.

#### Security Onion Server  

From Desktop:  

- Click Setup 
- Enter Password (fancy pass)
- Continue! 
- Configure network interfaces? NO!
- Select Production Mode
- Select SERVER!
- Select custom
- Create Sguil username (dcistudent)
- Create Sguil password (fancy pass)  
- Default numbers are good for the next two steps
- Select SNORT!
- Select Emerging Threats Open
- Enable Salt
- Disable ELSA
- Yes, proceed with the changes!
- Do not close the box until we do the next step!

Now, we need to make sure the firewall is OFF!

`sudo ufw disable`  
If you don't run this command before closing the dialog box, you will be locked out of the VM! You will need to SSH to the machine and close the firewall. This is because the server restricts all access except for SSH, and AWS obviously doesn't use that.

The IP is 10.10.10.5, you can simply Putty in from the WIN10 VM.

You can check information about the server and sensor with the following commands:  
`sudo sostat`  
`sudo sostat-quick`  

Click through the remaining dialog boxes and we are ready to move on to the sensor!

** NSM data/ <- storage for bro

#### Security Onion Sensor

From Desktop:  

- Click Setup
- Enter Password (fancy pass)
- Continue! 
- Configure network interfaces? NO!
- Select Production Mode
- Select SENSOR! 
- Enter the IP of the server: 10.10.10.5
- Enter the username of the user: dcistudent
- Select custom
- 4096 is fine here
- Enable the IDS engine
- Select OK
- Yes, enable Bro!
- Yes, enable file extraction (files stored to /nsm/bro/extracted)
- Yes, enable http_agent
- No, disable Argus
- No, disable Prads
- Yes, enable full packet capture
- Default pcap size is fine
- No, use default scatter/gather I/O
- Default ring buffer is fine
- Log purge % is fine
- Yes, enable salt
- No, disable ELSA
- Yes, proceed with the changes!

Again, we need to make sure the firewall is OFF!

`sudo ufw disable` 

Like before, if needed, we can Putty in to the sensor from the WIN10 VM. 10.10.10.7 is the sensor.

Note: Disabling the firewall cannot be done in advance because the setup will RE-ENABLE it!

### Workaround

---

#### Security Onion Sensor

From Desktop:  

- Click Setup
- Enter Password (fancy pass)
- Continue! 
- Configure network interfaces? NO!
- Select Production Mode
- Select STANDALONE! 
- Enter the IP of the server: 10.10.10.5
- Enter the username of the user: dcistudent
- Select custom
- Create Sguil username (dcistudent)
- Create Sguil password (fancy pass)  
- Default numbers are good for the next two steps
- Select SNORT!
- Select Emerging Threats Open
- Enable the IDS engine
- Select OK
- Yes, enable Bro!
- Yes, enable file extraction (files stored to /nsm/bro/extracted)
- Yes, enable http_agent
- No, disable Argus
- No, disable Prads
- Yes, enable full packet capture
- Default pcap size is fine
- No, use default scatter/gather I/O
- Default ring buffer is fine
- Log purge % is fine
- No, disable salt
- No, disable ELSA
- open terminal and type `sudo ufw disable`
- Yes, proceed with the changes!
- Wait for dialog box to be complete
- Run command in prompt
- Click OK


#### Verify configuration works!

`vi /etc/nsm/rules/rules.local`  
```
    1 alert icmp any any -> $HOME_NET any (msg:"Incoming ICMP packet"; sid:10000001;)
```
`sudo rule-update`  
`tail /etc/nsm/rules/downloaded.rules`  

We should see our written rules here!  

[Snorpy Rule Generator](http://snorpy.cyb3rs3c.net)  


We must ensure checksum is disabled in the snort config file!  
`vi /etc/nsm/so-sensor-eth0/snort.conf`  

```
    152
    153 # Configure IP / TCP checksum mode
    154 config checksum_mode:none
    155
```

Exercise 2.3-11

SCP pcap file over to sensor using WinSCP. Run TCPReplay to analyze BRO.  
`tcpreplay -t -i eth0 file.pcap`  

Where are bro logs stored?  
`/nsm/bro/logs`  
Notably, the current directory is the one we're interested in.  

Where are bro commands stored?  
`/opt/bro/bin`  

Where are extracted files stored?  
`/nsm/bro/extracted`  

What bro field uniquely identifies a file ID?  
`fuid`  

What command would you use to look at the following fields: timestamp, UID, IPs, filename, MIME type?  
`cat /nsm/bro/logs/current/files.log`  
`sudo cat /nsm/bro/logs/current/files.log | /opt/bro/bin/bro-cut ts fuid tx_hosts rx_hosts filename mime_type md5`  

What is the name of the files that were extracted?  
``  

What mime type was identified with the executable?  
``  

What is the MD5 of the executable?  
`` 

