# Mod 5 Exercise Notes
---

## Exercise 5-1-1 Provide Situation Report, Timeline and Operator Log of Activity.  
---

__Scenario__

The USCYBERCOM Commander is on-site. They have requested a brief to them and the supported command that explains what has happened so far. Due to the limited time, the CND Manager is going to ask you questions in order to understand the full picture before the briefing. These questions will be drawn from your previous exercises, and the information you possess will be used to complete the situation report (SITREP), timeline and this brief. If you have Operator Logs, they may be of significant use to you during this exercise.

The DCI CND manager is gathering information from each member of the DCI team. They are asking you, as the senior DCI member, to clarify some events that have happened during the mission before the brief.

__Background__

SITREPs are usually reported every 24-72 hours to higher headquarters (HHQ). These reports give insight to what has happened in the last 24, 48 or 72 hours and what is planned for the next 24, 48 or 72 hours.

Timelines help everyone understand what activity was recorded during an incident response, detailing the malicious activity from first seen to current findings. It is used to continue campaign analysis against an adversary and help future operations stop the malicious activity at the initial compromise stage of a kill chain. 

The operator log is a wealth of information. It can be used for de-confliction between the CPT and supported command. It also allows a greater understanding between the CPT members who are working shifts, because the log details every action taken on any machine. Operator logs also provide training to junior members with little or no experience. It allows those members to understand the flow of a mission and what commands or tools were used to accomplish each task. 



Action Summary  

Collect your previously saved operator logs for exercises.  
Answer questions in this exercise.  

Question 1  
During host discovery and enumeration, what two suspicious binaries were found on the Windows system? (Exercise 3.3-12: Analyze a Host to Identify Threat Activity)  

__FileHunter-Win32.exe__  
__extension.exe__   
firebird.exe  
Noise.dat  


Question 2  
What type of malware are the two suspicious binaries found on the Windows system? (Exercise 3.3-12: Analyze a Host to Identify Threat Activity)  

__Adware__  
Worm  
Remote Administration Trojan  
Exploit Toolkit  


Question 3  
What file was changed on the host machine since the baseline was made? (Exercise 3.3-12: Analyze a Host to Identify Threat Activity)  

__Noise.dat__  
ReAgent.xml  
notepad.exe  
deebeede.xml  


Question 4  
On the Windows machine, what three domains on the IOC list were contacted by the host? (Exercise 3.3-13: Analyze Hosts to Determine IOC Presence)

__deebeedesigns.ca__  
__firebirdonline.com__  
__thecrownsgolf.org__  
youtu.be  


Question 5  
What three IP IOCs were identified on the host machine? (Exercise 3.3-13: Analyze Hosts to Determine IOC Presence)  

__63.192.38.11__   
__65.110.1.32__   
__140.116.70.8__  
116.70.8.32  


Question 6   
The DCI CND manager wants to confirm that rouj.exe and runinfo.exe were the two IOCs identified on the host machine.

Were these files located on a host machine during the operation?(Exercise 3.3-13: Analyze Hosts to Determine IOC Presence)  

Yes  
__No__  


Question 7  
The Microsoft Edge browser attempts to connect to which URL? (Exercise 4.1-01: Investigate a False Positive)  

__https://youtu.be/dQw4w9WgXcQ__  
https://video.yandex.ru/dQw4w9WgXcQ  
https://microsoftvideo.com/dQw4w9WgXcQ  
https://video.yahoo.com/dQw4w9WgXcQ  

## Exercise 5-1-2 Provide SITREP and IOCs Identified for NETOPS  
---

__Scenario__

The USCYBERCOM commander is on-site. You have been requested to develop a timeline of DCI team activity and provide a SITREP to NETOPS. Your experiences and notes from previously completed exercises will be used to complete the SITREP and timeline.

__Background__

SITREPs are usually reported every 24-72 hours to higher headquarters (HHQ). These reports give insight to what has happened in the last 24, 48 or 72 hours and what is planned for the next 24, 48 or 72 hours.

Timelines help all stakeholders understand activities that occurred during an incident response; detailing the malicious activity from first sight up to current findings and actions. Timelines are used to perform campaign analysis about an adversary and help future operations stop this malicious activity at earlier stages of the Cyber Kill Chain.

The operator log is a wealth of information. It can be used for de-confliction between the CPT and supported command. It also allows a greater understanding between the CPT members who are working shifts because the log details every action taken on any machine. Operator logs also provide training to junior members with no experience. It allows those members to understand the flow of a mission and what commands or tools were used to accomplish each task.

__Action Summary__

Collect your previously saved operator logs for exercises.
Answer questions in this exercise.

__Scenario 1__

The DCI CND Manager has been advised of the progress of the current mission. Use your operator logs or other sources of information about previous exercises to answer key questions about different activities you have identified to date.


Question 1  
Per Exercise 3.2-06 Question 1:  
Use Nmap to scan the Class C network segment for 192.168.13.1. Which ports are open for the endpoint 192.168.13.17?  
__135 apparently (i've never seen this)__  

Question 2  
Per Exercise 3.2-06 Question 4:  
Which host is most likely a workstation?  
__192.168.13.32__

Question 3  
Per Exercise 3.2-08 Question 1:  
Based on Total Packets, what is the most talkative external/public IP address?   
__8.28.16.201__

Question 4  
Per Exercise 3.2-08 Question 6:  
Was an executable downloaded? Enter the name of the downloaded executable. If there is no evidence an executable was downloaded, enter "No".  
__pccleaner.exe__

Question 5  
Per Exercise 3.2-08 Question 10:  
What is the IP address of the domain for "smilecare.com?"  
__66.77.206.85__

Question 6  
Per Exercise 3.2-08 Question 11:  
What is the interval of the beacon?  

NOTE: Write your answer as: # seconds (Ex. 3 seconds)  
__60 seconds__  

Question 7  
Per Exercise 3.3-13 Question 1:  
List all domains that the host is connecting to that match the given IOCs. Provide your answer in alphabetical order with a space between each domain.  
Example answer: abc.com google.com tiger.com  
__deebeedesigns.ca firebirdonline.com thecrownsgolf.org__  

Question 8  
Per Exercise 3.3-13 Question 2:  
Which IOC’s were requested through the GET requests in the traffic capture?  
NOTE: Write your answer as: Blank.com and Item.gif  
__news\media\info.html__  
__SmartNav.jpg__  

Question 9  
Per Exercise 3.3-13 Question 5:  

Find the service name that matches the IOCs. What is the full path of the executable it references (including the executable itself)?  

Example answer: C:\path\to\bad.exe  

Service Name: __aec__  
Full Path: __C:\Users\DCI Student\AppData\Roaming\Microsoft\wuaclt.exe__  
`sc qc aec`  

Question 10  
Per Exercise 3.3-12 Question 1:  
Use GRR to perform analysis on the first system. Which binaries are found on the Windows system?  
__extension.exe__  
__Filehunter-Win32.exe__

Question 11  
Per Exercise 3.3-12 Question 2:  
Was persistence established in the registry?    

Yes  
__No__  

__Scenario 2__  

The DCI CND Manager needs you to complete a SITREP that will be sent to leadership who will forward it to NETOPS. The SITREP should include any significant findings detailing the true positive found. It also broadly details the actions conducted in the last 72 hours. The next 72 hours will be filled out by the DCI CND Manager. Using the SITREP example, in a group of no more than three people, complete a SITREP, detailing actions conducted once the true positive IOCs were found.  

Question 12   
Your supported NETOPS chain of command needs a SITREP of activity you have completed over the last 24 hours. Use the template to develop a SITREP and submit it here.  

__Note:__ You will be graded on the content in, not the layout of, the SITREP.  


```
LAST 24 HOURS

- OPERATORS IDENTIFIED APT IOC EXECUTABLE "pccleaner.exe" BEING DOWNLOADED ON LOCAL MACHINE FROM APT DOMAIN "smilecare.com" MATCHING IP ADDRESS ASSOCIATED WITH PREVIOUS APT ACTIVITY (66.77.206.85) 

- OPERATORS IDENTIFIED BEACON ACTIVITY TO APT DOMAIN LISTED ABOVE, "smilecare.com". TRAFFIC IS ENCRYPTED SO WE ARE UNABLE TO KNOW THE NATURE OF THIS CONNECTION, BUT THE DOMAIN HAS BEEN OBSERVED PREVIOUSLY ACTING AS A COMMAND AND CONTROL SERVER FOR APT.

- OPERATORS HAVE ADDITIONALLY IDENTIFIED THE FOLLOWING APT IOC'S IN THE NET TRAFFIC: 
    - deebeedesigns.ca
    - firebirdonline.com
    - thecrownsgolf.org

- HOST ANALYSIS REVEALED THE FOLLOWING HOST IOCs:
    - MALICIOUS PERSISTENCE ESTABLISHED VIA WINDOWS SERVICE "aec", REFERENCING IOC FILE FOUND AT "C:\Users\DCI Student\AppData\Roaming\Microsoft\wuaclt.exe". 
    - extension.exe
    - Filehunter-Win32.exe 

NEXT 24 HOURS

- FURTHER HOST ANALYSIS ON COMPROMISED SYSTEMS
- FURTHER NET ANALYSIS RELATING TO POTENTIAL C&C ACTIVITY
```

## Exercise 5-1-3 Select Appropriate Courses of Action to Mitigate Threats
---
[Mimikatz](https://attack.mitre.org/software/S0002/)  
[Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)  
[Threat Intelligence Reports](https://www.mandiant.com/resources/reports)  

__Stage 1 – Malicious software (malware) delivery and execution:__

- Adversaries perform reconnaissance to select a target user, and commonly send the user a malicious “spear phishing” email containing either a hyperlink to a website with malicious content or a malicious email attachment. Examples of such email attachments include an executable program, a Microsoft Office document containing a malicious macro, or a script file (e.g. JScript, VBScript, Windows Script File, HTML Application or PowerShell) – these files might be in a zip, RAR or other archive file. Alternatively, adversaries might compromise a legitimate website which the user is likely to visit, referred to as a “watering hole” or “strategic web compromise”.

- This reconnaissance is made easier for adversaries if the user’s name and/or email address are readily available via their employer’s website, social networking websites or if the user uses their work email address for purposes unrelated to work.

- Malware is then executed on the user’s computer and is often configured to persist by automatically executing every time the user restarts their computer and/or logs on. The malware communicates with “command and control” Internet infrastructure controlled by adversaries, usually downloading additional malware, enabling adversaries to remotely control the user’s computer and perform any action or access any data that the compromised user account can.

__Stage 2 – Network propagation:__

- Adversaries could use compromised account credentials, or in some cases exploitable security vulnerabilities affecting other computers in the organisation, to propagate (laterally move) throughout the network in order to locate and access sensitive data. Network propagation can occur rapidly on networks with inadequate network access restrictions, especially when multiple computers share the same local administrator passphrase. Data accessed frequently includes Microsoft Office files, Outlook email files, PDF files as well as data stored in databases. Adversaries typically access details such as the organisation hierarchy, usernames and passphrases including remote access credentials, as well as system data including configuration details of computers and the network.

- Although passphrases might be stored as cryptographic hashes to frustrate adversaries, these hashes can often be extracted by the adversary. Depending on the cryptographic strength of the hashing algorithm, these hashes might be cracked to derive the associated passphrases by using freely available software and a single computer or a publicly available cloud computing service. Some mitigation is provided by requiring all users to select a strong passphrase that meets or exceeds ISM requirements and is appropriately hashed using a cryptographically strong algorithm. Alternatively, adversaries might use a keystroke logger or the “pass the hash” technique, avoiding the need to crack passphrase hashes5.

- The use of single sign-on authentication in the organisation might significantly benefit adversaries. In contrast, the appropriate use of multi-factor authentication helps to hinder adversaries, especially if implemented for remote access, as well as for when users perform privileged actions such as administering a computer, and for when users access an important (sensitive or high-availability) data repository.

__Stage 3 – Data exfiltration:__

- Adversaries often use zip, RAR or other archive files to compress and encrypt a copy of the organisation’s sensitive data.

- Adversaries exfiltrate this data from the network, using available network protocols and ports allowed by the organisation’s gateway firewall, such as HTTPS, HTTP, or in some cases DNS or email.

- Adversaries might obtain Virtual Private Network (VPN) or other remote access account credentials, especially in the absence of multi-factor authentication, and use this encrypted network connection for exfiltrating data, with the aim of defeating network-based monitoring.

- Adversaries typically have several compromised computers on the organisation’s network, as well as compromised VPN or other remote access accounts, maintained as backdoors to facilitate further collection and exfiltration of data in the future. 

__Scenario 1__  

Currently the malicious activity has been isolated. The DCI team must lead the effort to determine the best course of action to contain and eradicate the malicious activity. The DCI CND manager wants the whole DCI squad to work together to develop the best course of actions to properly contain and eradicate the malicious activity. The DCI CND manager warns you to be prepared to make more than one COA, or adjust certain portions of a COA. The supported commander must approve the full COA before it can be implemented.  

Question 1   
Using the ASD documents, describe the mitigation strategies you would employ to detect or stop the delivery and execution (Stage 1 as defined in ASD – Mitigation Details) of the malware Poison Ivy. Explain why you chose these mitigation strategies.  

```
- Control attachments in emails. Don't allow downloading, previewing or execution of attached files. This will massively help to prevent phishing attempts.  
```

Question 2  
Using the ASD documents, describe the mitigation strategies you would employ to detect or stop the command and control (Stage 2 as defined in ASD – Mitigation Details) of the malware Poison Ivy. Explain why you chose these mitigation strategies.  
```
- Network segmentation. Logically separate machines that do not need to communicate.
- Two factor authentication for log-in
```

Question 3  
Using the ASD documents, describe the mitigation strategies you would employ to detect or stop the exfiltration of data (Stage 3 as defined in ASD – Mitigation Details) by the malware Poison Ivy. Explain why you chose these mitigation strategies.  
```
- Again, set up 2FA for log-ins. 
- Restrict VPN use on network
- Monitor files leaving net via IDS/IPS
- Monitor net connections via IDS/IPS
```

Question 4  
Using the ASD documents, describe the mitigation strategies you would employ to detect or stop the delivery and execution (Stage 1 as defined in ASD – Mitigation Details) of Mimikatz. Explain why you chose these mitigation strategies.   
`For this one, I would deploy an IPS with mimikatz signature loaded. It's a very well documented tool and this would prevent the most overt uses of it.`

Question 5  
Using the ASD documents, describe the mitigation strategies you will employ to detect or stop the command and control (Stage 2 as defined in ASD – Mitigation Details) of Mimikatz. Explain why you chose these mitigation strategies.    
```
- Further restrict password hashes. 
- Network segmentation. Logically separate machines that do not need to communicate.
```

Question 6  
Using the ASD documents, describe the mitigation strategies you will employ to detect or stop the exploitation (Stage 1 as defined in ASD – Mitigation Details) of Pass-the-Hash. Explain why you chose these mitigation strategies.    
```
- Restrict password hashes.
- Require two factor authentication
```

Question 7    
Stage 2 is accessing other systems using the hashed credentials the attacker obtained.    

Using the ASD documents, describe the mitigation strategies you will employ to detect or stop Stage 2 of Pass-the-Hash. Explain why you chose these mitigation strategies.    
```
- Network segmentation. Logically separate machines that do not need to communicate.
```

__Scenario 2__  

The DCI CND manager informs you that the supported command has placed a limitation on the COA development. They cannot support any COA with an upfront cost of HIGH. Answer the following questions, taking into account this new information.  

Question 8  
How does excluding web and email content filtering affect your mitigation strategy against Poison Ivy?  


Question 9  
How does excluding application whitelisting affect your mitigation strategy against Mimikatz?


Question 10  
How does excluding Network Segmentation affect your mitigation strategy against Pass-the-Hash?  


Question 11  
How would you eradicate Poison Ivy from the host machine?  
Revert to gold image  

Question 12  
How would you eradicate Mimikatz from the host machine?  
Revert to gold image  

Question 13  
How would you respond to the discovery of Pass-the-Hash on the host machine?  


Question 14  
The supported command has informed the CPT that the host machine cannot be taken offline, as it is a mission-critical asset. The supported command also does not want to re-image the machine at this time. Choose the best approach to eradicate malware.  

From the operation list below, identify the correct order of operation and provide your rationale. (E.g. first, second, third, fourth and fifth)   

1) Kill active processes
2) Remove abnormalities
3) Verify installed programs
4) Verify service list
5) Run packet capture

## Exercise 5-1-4 Risk Mitigation Tools and Techniques  
---
[OpenVAS Guide](https://www.kali.org/blog/configuring-and-tuning-openvas-in-kali-linux/)  
[Powershell Firewall guide](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2022-ps&viewFallbackFrom=win10-ps)  
[.Net Framework Objects](https://learn.microsoft.com/en-us/dotnet/api/system.net?view=netframework-4.7.2)  

__Scenario__  
You’ve received a warning order (WARNO) describing a mission your team will be assigned to soon. Your team's role in this mission will be to mitigate risk for the network. Your team has decided to use tools from your CPT toolkit that would be relevant and useful to this role.  

__Background__  
Training beforehand is vital to mission success. Before leaving for a mission, your team should know what tools and equipment to use, the tools' capabilities and limits, and the scope of the mission.

You should also be aware of outside resources and organizations that could be critical to your success. No one person or even cyber team can know every aspect of networking and cybersecurity, so maintaining communication between your team, the local defenders and any other organizations could be resources for guidance and advice.

__Action Summary__  
Read OpenVAS and PowerShell guides on how to use these tools effectively.
Use the tools to answer questions for this exercise.

```
Setup OpenVAS
Connect to 10.10.30.11 from Win10 chrome browser  
Task Wizard(little wand) > run and view scans

Putty into OpenVAS server 10.10.30.11 (root/toor)  


```

---
Question 1  
From the set of scans, which IP address has the highest-severity vulnerability number and what is the value?  
Select one.  
__10.10.10.10-12 and 9.3__  
10.10.10.13 and 9.3  
10.10.10.10-12 and 6.4  
10.10.10.13 and 6.4  


Question 2  
Which IP address, or range of IP addresses, has the vulnerability "CGI Scanning Consolidation"?  
Select one.  
__10.10.10.10 - 10.10.10.12__  
10.10.10.11 - 10.10.10.13  
10.10.10.12  
10.10.10.13  


Question 3  
Next, run an authenticated scan for SMB using: 

OpenVAS  

Username: Administrator
Password: P@ssw0rd

Run an authenticated scan for SSH using: 

Username: student
Password: P@ssw0rd

For 10.10.10.10: List the total amount of high and medium severity vulnerabilities that are reported.  
24  

Question 4  
For 10.10.10.10: List the total amount of vulnerabilities that are fixed by vendor patches.
11  

Question 5  
For 10.10.10.10: List how many total vulnerabilities have workarounds.  
3  

Question 6  
For 10.10.10.10: List how many total vulnerabilities require mitigation.  
8  

Question 7  
What is the highest-severity vulnerability, and on which IP address is it?  

9.3 and 10.10.10.10  
9.3 and 10.10.10.13  
10 and 10.10.10.10  
__10 and 10.10.10.13__  


Question 8  
How many critical risks did MBSA find?  
4  


Question 9  
How many user accounts had blank or simple passwords?  
3

Question 10  
How many shared folders are present on the system?  
2

Question 11  
Is Windows Firewall enabled or disabled?  
Enabled  
__Disabled__  


Question 12  
What should RestrictAnonymous be set to for the best security?  

Select one.  
__2__  
0  
1  
3  


Question 13  
From the following, which are the recommended Audit options in the Audit Policy. (Select all that apply.)  

__Audit account logon events__  
__Audit system events__  
Audit network events  
Audit hardware access  

Question 14  
What is the process name listening on port 21 on 10.10.10.10?  
FileZillaServer  

Question 15  
What is the PowerShell command to create a firewall rule?  
New-NetFirewallRule  

Question 16  
How many users are registered on the SQL Server (IP 10.10.10.11)?  
7  

Question 17  
What command would be used to modify the password of a local user?  
Set-LocalUser  

Question 18  
What .net framework object would be used to download and upload FTP files?  

Select one.  
__System.Net.Webclient__  
System.Net.EndPoint  
System.Net.NetworkAddress  
System.Net.Authorization  


## Exercise 5-1-5 Installing and Configure Snort on Windows  
---

[Snort User's Manual](http://manual-snort-org.s3-website-us-east-1.amazonaws.com)  
[Installing Snort of Winders](https://zaeemjaved10.medium.com/installing-configuring-snort-2-9-17-on-windows-10-26f73e342780)  
[Snort Rule Validator](https://marcusliberto.com/SRV/index.html)  

__Scenario__

Now that the election has ended, your team must continue to secure the network. The CTE squad has been assigned to create software to emulate advanced persistent threat (APT) effects on the network. You have been assigned to install and configure Snort on each of the local defenders' machines. As the CTE squad is still working on creating its threat emulation software, you will be provided with a sample program and test rules to verify that your Snort configuration works correctly.  

__Background__

Snort is one of many tools used to analyze network traffic and issue alerts based on criteria such as IP addresses, domain names and packet content. For DCI squad members, it is essential to use intrusion detection system (IDS) tools effectively to determine if an APT is present on the system. Many Snort community rules are available to detect most common threats, but new and emerging threats are created daily. The threats to your mission's networks may be unique. By understanding how to install and configure Snort, you can monitor a network for specific threats.  

__Action Summary__  

Configure Snort to correctly monitor the network.  
Answer questions in this exercise.  

__Snort on Windows__  

Install Snort (located in C:\Downloads on Local Administrator VM).  

Using the Snort guide and online resources, configure Snort to correctly monitor the network.  

```
Pretty much just let the wizards do the thing to install it.
cd to c:\snort\bin and run snort -V to ensure it downloaded properly.
Create local.rules file in c:\snort\rules
Download notepad++ from share drive, open c:\snort\etc\snort.conf

config logdir: c:\Snort\log

# path to dynamic preprocessor libraries
dynamicpreprocessor directory c:\snort\lib\snort_dynamicpreprocessor
# path to base preprocessor engine
dynamicengine c:\snort\lib\snort_dynamicengine\sf_engine.dll
# path to dynamic rules libraries
# dynamicdetection directory /usr/local/lib/snort_dynamicrules

I also got rid of every rule except for local.rules. 

For some reason I'm not seeing any answers. My rule flags traffic, there just isn't the traffic that I'm supposed to see? I was supposed to do all this on the voter server, duh. Set it up over there and we got plenty of alerts to look at!
```

Make rules to monitor the following:  

–  Any TCP connections to 10.10.10.10    
    `alert tcp any any -> 10.10.10.10 any (msg:"TCP connection to 10.10.10.10";sid:10001;)`    
–  Any UDP connections to 10.10.10.10   
    `alert udp any any -> 10.10.10.10 any (msg:"UDP connection to 10.10.10.10";sid:10002;)`  
–  Any TCP connections to 10.10.10.10 containing the content "delete"    
    `alert tcp any any -> 10.10.10.10 any (msg:"Content 'delete' detected";content:"delete";sid:10003;)`  
–  Any connections that contain the content "drop"    
    `alert ip any any <> any any (msg:"Content 'drop' detected";content:"drop"; sid: 10004;)`

After making these rules, run Snort and then run Test.exe. If configured correctly, this should allow you to answer the following questions.  

Snort for Windows is an unusual system and can be difficult to configure. Don’t be afraid to take advantage of resources available online. In addition, once it’s installed, the following command can be used to run Snort to ensure that it is using your configuration file correctly.

.\snort.exe -i 1 -c C:\Snort\etc\snort.conf -A console -l c:\snort\log -K ascii

__Instructions__  
 
Access the resource drive using SMB and connect to: IP: 10.10.10.100   
Use a web browser to connect to: IP: 10.10.10.100  

Question 1  
How many total TCP connections were made to 10.10.10.10?  
9  

Question 2  
How many total UDP packets were sent to 10.10.10.10?  
5  

Question 3  
The UDP communication used what port?  
53  (8000?)  

Question 4  
How many TCP connections to 10.10.10.10 contained the content "delete"?  
1

Question 5  
How many connections contained the content “drop”?    
3


## Exercise 5-1-6 Provide Risk Analysis Based on an RMP
---

[NIST Risk Assessment](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf)  
[APT 1](https://www.mandiant.com/resources/reports/apt1-exposing-one-chinas-cyber-espionage-units)  


Question 1  
Previously, the CPT decided to ensure that email content filtering was implemented by the supported command. This can stop certain attachments from being sent and opened. The supported command did not want to implement web content filtering. What risk is left over in this example? How can an adversary use the lack of web content filtering to deliver its malware?  
Leftover Risk - highly vulnerable to phishing attacks. the most sophisticated attacks don't require user interaction. if you don't filter out certain file types you are leaving a gaping hole in your network.  


Question 2  
The supported command ensured that the strategy of least privileges was implemented. The IT staff must now type in their credentials on each machine before allowing any software or applications to be installed. A DCI analyst noticed that all the IT staff were using the same local administrator account username and passwords. Is this a risk? If so, how do you recommend addressing this risk?  
Yes, this is a risk. All users should have unique accounts. Not only for accurate logging purposes, but sharing an account across the domain allows for easier propogation for an adversary.  


Question 3  
The supported commander has conducted user education on phishing and has ensured that their IT staff has used the Block Spoofed Emails mitigation strategy. Is there any leftover risk? If so, what is it?  
Yes, the end user is always the weakest link. Phishing will always be an effective vector.  

Question 4  
The supported command has approved and implemented blacklisting of applications and devices. The supported commander wants to know if this will stop the execution of malicious applications that somehow make it onto their machines. How would you respond?  
Yes and no. Blacklisting will permit any file that isn't explicitly listed. If you know what files are coming you can prevent them, but you can't prevent what you can't see. If the network can support it, I recommend whitelisting instead of blacklisting.    

Question 5  
The supported commander does not want to block Facebook or Twitter because of morale concerns. He wants more information on the benefits of blocking these websites and applications. How can an adversary use these platforms to deliver a malicious payload?  
 1. malicious links
 2. phishing
 3. open source research

Question 1   

An adversary could deliver malware through web-based email services or Phishing . Without web content filtering, users are more likely to click on malicious links or download malware from websites accessed via email links or attachments. An adversary can use any website for malware delivery, C2, and exfiltration that is not blocked by another mitigation.  

Question 2   

It creates a single point of failure, making it easier for potential attackers to gain unauthorized access to systems if they obtain these credentials. To address this risk, establish individual accounts for each IT staff member with strong, unique passwords, implement regular password rotations, and enforce two-factor authentication where possible. Additionally, conducting regular audits, providing security training, and maintaining strict access controls are essential to mitigate this risk and bolster overall cybersecurity.  

Question 3   

Advanced and targeted phishing attacks, like spear-phishing, may still pose a threat as they can bypass standard spoofed email detection methods.  Blocking Spoofed Emails mitigation does not prevent emails that are not spoofed to be from the listed domains. Therefore any emails not spoofed in this way will still be allowed through and can contain malicious links or attachments. This is including e-mails from domains obfuscated to be very similar to the organizations domain, but not an exact match. Forwarded emails also may bypass SPF.    

Question 4   

Blacklisting applications and devices can help prevent known malicious applications from running, but it may not stop new or unknown threats. It's advisable to combine blacklisting with other security measures like whitelisting and behavior-based monitoring for comprehensive protection against a wider range of threats.  

Question 5   

Adversaries can misuse these platforms by posting malicious links or attachments in seemingly harmless posts, direct messages, or advertisements. This could open up to possible company targeted phishing attempts. Facebook and twitter accounts are compromised frequently and can be used to deliver links to people that trust the account and will be very likely to click on the link.  

## Exercise 5-1-8 Generate and Implement a RMP for a Network (Capstone)  
---

__Introduction__  

This exercise will work through generating and implementing a risk-mitigation plan (RMP) for a given network. You will use the tools from previous exercises and class to determine the risks for this network, implement solutions, and document known risks that you do not mitigate.

Windows Voting Database Server:   
IP Address: 10.10.10.11  
Username: Administrator  
Password: P@ssw0rd  
SQL (1443)  
Stores voting data.  


Windows Voting Email Server:   
IP Address: 10.10.10.12  
Username: Administrator  
Password: P@ssw0rd  
SMTP (25)  
IMAP (110)  
Sends confirmation emails for votes and is used for help.  


Linux Backup Server: 
IP Address: 10.10.10.13  
Username: student  
Password: P@ssw0rd  
FTP (20 & 21)  
Backup Server. (Recently acquired, but not configured)  


Windows Local Administrator: 
IP Address: 10.10.20.10  
Username: Administrator  
Password: P@ssw0rd  
RDP (3389)  
Local defender administrator workstation.  



__Scenario__

Your team has been instructed by the mission owner to develop an RMP for a subnet on the local defenders’ network. A controversial election is taking place soon between Travis Floyd and Matthew Cooper. This network is responsible for hosting the voting web interface and database servers.  

While on site, you noticed the security for this operation is extremely lax. The administrator of the network has shared passwords with multiple IT specialists on the team. Regulations on need to know and role-based access have not been followed. You also notice that some team members heavily favor one candidate over the other, and therefore have an incentive to manipulate the votes. Also, lazy administrators have disabled the firewall for convenience, leaving an enormous attack surface, meaning you need to set all firewall rules at the host level. The administrator also recently just got a Linux server for backup purposes for the website and database via FTP but has not set up a backup script. You have eight hours to create and implement an RMP for this network before the voting begins.  

__Background__

An RMP is a document that communicates risk to local defenders and mission owner and recommends actions to mitigate those risks. It also conveys risks that are to be accepted. This can be a sensible action if the cost of mitigating the risk is higher than the cost and chance of exploitation of the risk. Although some CPT missions have mitigations implemented by local defenders, this exercise allows you to implement these mitigations yourself. In this way, you gain a deeper understanding of the cost of time, labor and expertise needed to implement these mitigations. An RMP is implemented before an attack occurs. It is a preventive, proactive measure, not a reactive one. It addresses the reconnaissance, weaponization and delivery steps of the Cyber Kill Chain. In future exercises, we will discuss a mission-defense plan (MDP). This document is used for defending a network under active attack.

__Action Summary__  

1.  Read the Cyber Kill Chain document and view the RMP template.
2.  Enumerate the network using tools and network knowledge available to you.
3.  Create an RMP document.
4.  Implement courses of action (COAs) from your RMP document.
5.  Test COA effectiveness by executing an attack simulation. 

__Generate a Risk-Mitigation Plan__

Applying what you've learned in previous modules, discover vulnerabilities in the network. Document these vulnerabilities in your RMP. Then, either document your mitigation measure and implement it, or accept the risk and document why. Go to the next page once all your risk mitigations have been implemented. Make sure to refer to the Local Defenders Network document for provided services.  

__Rules__

Do not manipulate the user account "Grading" on any box. This account's purpose is to automatically grade your success in defending the network. Do not change the password or delete the username.  
Your toolkit and the local administrator need PowerShell access to all Windows boxes, SSH to all Linux boxes, and FTP access to the voting server and the FTP backup server.  

__Guidelines__

No malware or existing malicious backdoors are built into any of the systems. This exercise is for risk mitigation, not an active attack on a network. However, current services installed could still be used for a malicious purpose. SSH and RDP can be used legitimately, but they can also be used in a malicious way.
Your toolkit is secure and will not be touched or leveraged by the malicious actors.
Any machine not documented in the local defenders’ network that you can find in an Nmap scan using your toolkit should be left turned on, but they should not be allowed to access the documented network. Any service not documented by the local defenders can be turned off.
Any box on the local defenders’ network can be leveraged to access other boxes.
Scanning only needs to be done in 10.10.10.0/24 and 10.10.20.0/24.
Occasionally, the system will think services are down when they are not. This is expected. Your score is rounded up by 5 points, which more than compensates for this.
When running the attack executable, run it from within a command or PowerShell prompt. Otherwise, it is easy to miss when it gives an error before closing and it will appear not to be functioning correctly. 
You should take steps to secure the passwords for the various accounts on the network. However, the Local Administrator still needs to be able to carry out their duties, so they will need the password for a working Admin account on the various Windows devices, as well as a working FTP Credential. This account should have the same password on each device, but it does not have to be the original Administrator account or the original password.

__Setting up your Inbox__

Before simulating the attack, you need to set up your email on the CPTDCI Admin box. To do so, perform the following steps:  

1. Open the Mail application from the Start Menu.
2. Select Add Account and then Advanced Setup.
3. In Email Address, enter CPTDCI@votetoday.com.
4. In User Name, enter CPTDCI@votetoday.com.
5. In Password, enter P@ssw0rd.
6. In Account Name, enter CPTDCI@votetoday.com.
7. In Send your messages using this name enter CPTDCI.
8. In Incoming email server, enter votetoday.com.
9. In Account Type, enter POP3.
10. In Outgoing email server, enter votetoday.com.
11. Uncheck Require SLL for incoming email and Require SSL for outgoing email.
12. Press Sign in.

The local administrator will email you during the attack, so watch your inbox to stay informed about the adversary’s actions.  

__Instructions__  

Connect to the Local Defender Administrator Box and execute SimulateAttack.exe on the Desktop.  
After two hours, a grade along with a hash will pop up on the screen. This hash is proof of your grade.  
Continue to check your email as your interaction may be necessary.  

You will be graded on two criteria:
1. Keeping the voting website functional   
2. The ability of the administrator to access and update boxes.  

If you do not receive 90% or better on this exercise, delete and rebuild your stack and try again.  

If you receive 90% or better and other students are still working, proceed to the Extra Mile exercise.  

At the end of this exercise, the instructor will go over with the class what the attackers attempted to do and the mitigation strategies to prevent this event from occurring.  


__Extra Mile:__  

Attempt to create yourself as a third candidate on the website and win the election.  

Question 1  
Using the information obtained during your vulnerability assessment and network enumeration, what is the perceived threat to the Maryland Board of Elections?  

Question 2  
List the perceived impact to the mission represented by each of the following Cyber Key-Terrain:  
Voting Server  
VoterDB  
Email Server  
FTP Server  

Question 3  
If you received any email notifications, what were they and how did you fix the issue?  


Question 4  
The web developer has created a means of easily managing the users included in the election. This file needs to be found and secured to prevent potential tampering, what is the file name?  



### Actions taken
---

nmap scan for ports open, hosts on net 10.10.10.0/24 and 10.10.20.0/24  
iptables/firewalls blocking external ssh/ftp connections
change passwords  
set up backup server to host important files - all vote db files need to be backed up  
microsoft baseline security analyzer??? where tf?  

run `openvas-setup` on openVAS vm, followed by `openvas-start`. then connect to 10.10.30.11 from win10 machine.  (admin / P@ssw0rd). Select scans and the wizard wand, then you can run scans.    

OpenVAS results  
10.10.10.13 (Linux Backup Server)  
- anonymous FTP login allows (disable anonymous access)  
- FTP cleartext login (how do you fix this? thats like the big thing about ftp)  
- Telnet cleartext login (block telnet, move to SSH)  
- http server active, disable  
- create administrator /   

10.10.10.12 (Voter Email Server)  
- vulnerable to eternal blue. PATCH IMMEDIATELY!  
- SMTP, POP3 cleartext login. enable encryption!    
- Deprecated TLS/SSL - install latest update  
- change admin password `net user administrator newpass`  
- disable guest `net user guest /active:no`  
- firewall `enable-netfirewallrule`

10.10.10.11 (Voter DB)    
- Vulnerable to eternal blue. PATCH IMMEDIATELY!     
- FTP cleartext login     
- Deprecated TLS/SSL - install latest update  
- change admin password `net user administrator newpass`    
- disable guest `net user guest /active:no`    
- firewall `enable-netfirewallrule`  

Apparently I wasn't supposed to touch the .11! Would've been nice to have in writing!  

Administrator /   
After changing the pass, our PsSession will end and we will need to re-enter the session.  

```
Nmap scan report for 10.10.10.11
Host is up (0.00034s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
3389/tcp open  ms-wbt-server

Nmap scan report for 10.10.10.12
Host is up (0.00047s latency).
Not shown: 992 closed tcp ports (reset)
PORT     STATE SERVICE
25/tcp   open  smtp
110/tcp  open  pop3
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
143/tcp  open  imap
445/tcp  open  microsoft-ds
587/tcp  open  submission
3389/tcp open  ms-wbt-server

Nmap scan report for 10.10.10.13
Host is up (0.00039s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
23/tcp    open   telnet
80/tcp    open   http
443/tcp   closed https
445/tcp   open   microsoft-ds
5901/tcp  open   vnc-1
8080/tcp  closed http-proxy
8888/tcp  closed sun-answerbook
31337/tcp closed Elite

Nmap scan report for 10.10.10.100
Host is up (0.00022s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap scan report for 10.10.10.104
Host is up (0.00043s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
3389/tcp open  ms-wbt-server

```

From big brain jacobdouglas40  

One thing I did is disable anonymous login on the FTP server. By editing /etc/vsftpd.conf and changing the line that allows it from YES to NO and doing a service vsftpd restart.   

I changed all passwords for every user and disabled all extra accounts like Guest, sshd, and User.   

I created a script that uses winscp to automatically backup important server files to the FTP server. Then made a scheduled task for it.   

I disabled the ssh service on the VoterDB server.  

Here's an example command with a script to setup automatic backup for FTP "C:\Program Files (x86)\WinSCP\WinSCP.com" /script="C:\Users\DCI Student\Desktop\backup.bat"   
```
    option batch abort
    option confirm off
    option transfer binary
    open ftp://student:P@ssw0rd@10.10.10.13:21
    pwd
    put C:\backup\* /"Voting Backup"/10.10.10.10/backup/
    put C:\xampp\* /"Voting Backup"/10.10.10.10/xampp/
    put C:\VoteDB\* /"Voting Backup"/10.10.10.10/VoteDB/
    pwd
    exit
```