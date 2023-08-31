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