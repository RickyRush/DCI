## Mod 6 Exercise Notes
---

## 6-1-1 Re-baselining a Network  
---

__Introduction__  
In this module, students return the defended network to the closest possible norm for re-deployment and perform a variety of closeout reporting activities to include the out-brief with security recommendations and after-action reports.  

Module Objectives  
Upon completion of this module, you will be able to:  

Return network to "normal" or closest possible  
[Compile final reporting and perform other mission closeout activities]  

In this lesson, students demonstrate the removal of host- and network-based sensors from a network environment and ensure that systems remain operational. Students develop and implement strategies to recover systems when removal of sensor capabilities causes system failure. Students develop a final out-brief to include recommendations to enhance the security posture of the network. Students perform an after-action report per USCYBERCOM guidelines and provide input specific to the DCI areas of responsibility.  

Upon completion of this lesson, you will be able to:   

Perform removal of all host and network sensors  
Review DCI results for supported commander and provide recommendations to secure network in the future  
Conduct after-action report  

__Scenario__  

The DCI team leader has tasked you with the network re-baselining, as well as removal and cleanup of the environment. Your only limitation is you cannot log on to the workstations to clean up any potential WinRM ports left open. The local defenders will clean up the hosts after you return to home station. You can still access the servers on the network.    

__Action Summary__   

Run an Nmap scan on the network to determine what ports have been left open.    
Add missing devices to an updated network map.    
Close ports opened by the CPT during the mission.    
Stop services started by the CPT during the mission.    
Retrieve event logs from the Windows server.    
Create a Final Report of the artifacts in the IR Drive.    
Wipe the mission owner data from the IR Drive.    

__Resources__  
[Top 1000 NMAP Ports](https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/)  
[WinRM Service Port](https://learn.microsoft.com/en-us/archive/blogs/christwe/what-port-does-powershell-remoting-use)  
[Grep Man Page](http://linuxcommand.org/lc3_man_pages/grep1.html)  
[dc3dd Tool Usage](https://manpages.ubuntu.com/manpages/lunar/en/man1/dc3dd.1.html)  
[Removing the GRR Agent](https://grr-doc.readthedocs.io/en/v3.2.1/deploying-grr-clients/on-windows.html)  
[Retrieving Windows Event Logs](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1)   



Win10  
Username: DCI Student  
Password: P@ssw0rd  

Kali/GRR  
Username: root  
Password: toor  

Windows Server  
Username: Administrator  
Password: P@ssw0rd  



__Scenario:__   

The local commander is requesting an updated network map. Use NMAP on the Kali machine to scan the 172.29.234.0/24 network. Local defenders identified that 172.29.234.32 was not supposed to be on the live network and removed the device. They need to know what IP addresses remain that are not listed on the network map.  

Perform an NMAP Scan (questions 1-3)  

Question 1  
The local defenders have added a firewall that is blocking ping and a basic scan that will return a list of ports that are all filtered if not open. What IP address needs to be added to the network workstations' baseline?   
__172.29.234.5__  
`nmap -n -Pn -T5 172.29.234.0/24`  

`restart-computer win-voteDB -force`  

Question 2  
How many workstation IP addresses can be verified to have WinRM running? (ports 5985,5986)    
One (?)  

Question 3  
Run a scan on the 172.16.8.9 address. With the scan results given, could you guarantee that the WinRM port was running on the server?  
__Yes__  
```
┌──(root㉿kali)-[~]
└─# nmap -p 5985,5986 172.16.8.0/24
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-12 12:59 UTC
Nmap scan report for ip-172-16-8-9.ec2.internal (172.16.8.9)
Host is up (0.00066s latency).

PORT     STATE  SERVICE
5985/tcp open   wsman
5986/tcp closed wsmans

Nmap done: 256 IP addresses (1 host up) scanned in 4.10 seconds
```

__Clean Up the Windows Server__  
(questions 4-5)

You could not identify whether WinRM was running on the Windows server, and it needs to be checked, but a GRR agent is installed. In C:\ there is an executable named verify.exe. Your next task is to remove any traces of the GRR agent and run the executable to make sure the box is clean. If you accidentally delete it, there is another copy in the resources drive on the Windows 10 host. Copy verify.exe over to the server and run it from there.   


Question 4   
The first step on the server is checking to see if WinRM is stopped from accepting remote connections. When complete, run check_winrm.exe which is on the Windows server's C:\. What was the response from the executable when successful?  
`disable-psremoting`  
`stop-service winrm`  
`.\check_winrm.exe`  
Good job! The code is: __w1nrmvd__  

Question 5   
The next step is to remove any traces of the GRR agent from the box. Once complete, run the executable to verify GRR is removed. What is the code that the executable provides once you have removed the agent?   
`sc stop "grr monitor"`  
`%systemroot%\system32\grr\*`  
`HKEY_LOCAL_MACHINE\Software\GRR`  
```
sc stop "grr monitor"
sc delete "grr monitor"
reg delete HKLM\Software\GRR
rmdir /Q /S c:\windows\system32\grr
del /F c:\windows\system32\grr_installer.txt
```

Successfully removed GRR! Code is: __R3m0v3dG44__  

__Gather the Windows Event Logs__   
(questions 6-9)  

The last thing needed for the Windows server is to identify what was left on it in the form of event logs. Your task is to identify what logs were created when you remoted into the machine previously.

`get-eventlog -logname Security -Message *172.16.12.3* | select -ExpandProperty message | findstr "Source Port"`  

`Get-EventLog -LogName Security | where-object {$_.message -like "*172.16.12.3*"} |Select -first 5000 | select -ExpandProperty Message | findstr "Port" | ForEach-Object {$_.split(":")[1]} | group-object -NoElement`  

Question 6  
What source ports have been used by the CPT's Windows 10 host? Note: Look for IP 172.16.12.3. There are 12 total results, but select only from the following:  
__50726__  
__65497__  
65499  
56842  

`get-eventlog -logname security -message *172.16.12.3* | select -expandproperty message | findstr "Impersonation Level"`  

Question 7  
What impersonation level was found to be used by the remote logon from the CPT's Windows 10 host?  
__%%1833__  
%%1834  
%%1843  
%%1844  


Question 8
What does the above impersonation level answer represent?  
Admin creds to log in using NTLM  


`(get-eventlog -logname Security -InstanceId 4624 -Message *172.16.12.3*).count`  
Question 9  
How many times, before today, does the Instance ID of 4624 show up corresponding to the IP address 172.16.12.3?  


__Create a Final Report__ 
(question 10)   

Your next task is to summarize what you found and accomplished on the mission.  

Question 10   
Using the artifacts located in the IR drive, as well as previous findings, write a report on everything you have accomplished and found while on mission.   

Note: This report is built from everything from APT 1. Include other names it is known by and what you have found to date. Be sure to include the IOCs found with Snort, GRR and PowerShell. The easiest way to accomplish this is to look at the individual files in the IR drive. There should be at least a sentence a piece on each file.

```
The following IOCs were found on hosts in the mission partner network:

  - adobeUpdater.exe
  - 1.zip
  - image.bmp (used to obfuscate a message)
  - Registry file IOCs include:
	  - iTunesHelper.exe
	  - start.bat
	  - wuauclt.exe

These were found in the Run keys so that these files would execute when the user logged in.


The following domain IOCs were observed in network traffic:
  - smilecare.com
  - update.sektori.org
  - download.epac.to
  - drgeorges.com
  - news.hqrls.com
  - kayauto.net (beacon)
  - gobroadreach.com (beacon)

NOTE: the domains marked beacon are connecting to domains that are associated with command and control activity via beacon.  This means malware has been installed on a host and it is making an outbound connection to a malicous actor (likely APT1)
```


__Scenario: Wipe the IR Drive__   
(question 11)  

Using dc3dd, wipe the mission data from the IR Drive and verify with xxd. Use the hex pattern 0xdac1.  

`fdisk -l`  
`dc3dd wipe=/dev/nvme1n1 pat=dac1`  
`xxd -s 901 -l 1 /dev/nvme1n1`  

Question 11  
What value is represented at the 902nd byte after running xxd? __0 index! Keep in mind when running xxd__

![Alt text](image-5.png)