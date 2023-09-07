# Mod 4 Exercise Notes
---

## Exercise 4-1-1 Investigate a False Positive
---

Question 1  
What happens when the user runs the Google Chrome browser?

It opens directly to "https://youtu.be/dQw4w9WgXcQ"  



Question 2  
The browser attempts to connect to what URL?  
youtu.be - more specifically, it rick rolls the user  


Question 3  
Was the target of the Google Chrome shortcut altered?  
Yes  
__No__ 


Question 4  
Identify the target of the Google Chrome shortcut and state where it is located.  

NOTE: Use the file path to state where it is located.
"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"



Question 5  
Does the hash of the chrome.exe match a known Chrome executable?  

Note: It is a bad practice to put hashes into VirusTotal. Adversaries are known to monitor the website in order to see if their malicious activity has been found. For this course, it is fine but you could also compare the hash file against your local machine!  
`get-filehash -a md5 "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`  
7D48976F85456176A02903B466C92CE4  
Yes   
No  

This hash is not recognized by virus total, and it doesn't match chrome.exe on my local machine.    

Question 6  
The user reported that the browser starts automatically after a reboot. Where would be the best places to look for artifacts?  
Registry run keys  

Question 7  
Is there a registry value associated with the suspicious executable? If so, what is it?
```
PS C:\Program Files (x86)\google\chrome\Application> Get-Item -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Ru


    Hive: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion


Name                           Property
----                           --------
Run                            Google Chrome Updater : C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
```

Question 8  
What is the value data?  

Question 9  
Is it likely that this incident indicates an APT1 actor?  
Yes, it is likely an APT.  
__No, it is not likely an APT.__  


Question 10  
Why do you think this is not a likely APT threat? What seems to be the cause of this incident?  
homie got PRANKED!  


## Exercise 4-1-2 Investigate a True Positive  
---

Question 1  
Identify if there are indicators of compromise in the registry.  
`Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` 
I would say yes - sus values in run key.   

Question 2  
If you identified IOC's, what group of keys appears to be modified?  
```
PS C:\Users\DCI Student> Get-Item -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run


    Hive: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion


Name                           Property
----                           --------
Run                            OneDrive      : "C:\Users\DCI Student\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
                               /background
                               MattIsAwesome : %LOCALAPPDATA%\MattIsAwesome.exe
                               LastEnum      : %LOCALAPPDATA%\Microsoft\VMwareManager.exe
                               ItunesHelper  : %TEMP%\ituneshelper.exe


```

Question 3  
List the values that may be IOC's.  

Note: Although all IOC’s are reportable, VMwareManager.exe and LastEnum are not the focus for this exercise.  
```
                               MattIsAwesome : %LOCALAPPDATA%\MattIsAwesome.exe
                               LastEnum      : %LOCALAPPDATA%\Microsoft\VMwareManager.exe
                               ItunesHelper  : %TEMP%\ituneshelper.exe
```

Question 4  
Identify any files that could be indicators of compromise. Include the absolute paths.  
```   
Directory: C:\Users\DCI Student\AppData\Local

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/21/2017   4:02 AM        6999275 MattIsAwesome.exe


Directory: C:\Users\DCI Student\AppData\Local\Temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/21/2017   4:02 AM        6999275 ituneshelper.exe

```

Question 5  
Is there evidence that ituneshelper could generate any network traffic? (Yes or No)  
Note: Use Select Strings in PowerShell with regex to filter out the IP Address.  
Yes  
No  
`.\strings.exe .\ituneshelper.exe | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}"`  

Question 6  
What is the private IP address the malware is trying to reach out to?  


Question 7  
Is this activity characteristic of APT1 activity?  

__Yes. The artifacts from this malware match the characteristics of APT1.__  
No. The artifacts from this malware do not match the characteristics of APT1.  



## Exercise 4-1-3 Analyze Network Traffic to Identify a Beacon  

Question 1  
What protocol contains a beacon that has a set interval between each beacon?  
__FTP__  
ICMP  
HTTP  
HTTPS  

IO Graph - filter for FTP. You can see a bit of a "heartbeat"  

Question 2  
What is the interval of the beacon in seconds?  
__60__  
30  
90  
120  


Question 3  
What is the IP address the beacon is reaching out to?  
66.220.9.50  

Question 4  
What percentage of the pcap is used by the packets between this beacon and the host machine?  
0.2%  
1.7%  
0.01%  
3%  


Question 5  
What protocol contains a beacon that has a random interval?  
ICMP  
FTP  
HTTP   
HTTPS  


Question 6  
What is the range of the randomness of the interval?  
2-10 minutes  
1-5 minutes  
1-2 minutes  
5-10 minutes  


Question 7  
What is the IP address the beacon is reaching out to?  


Question 8  
What is the Checksum of the first communication of the beacon? e.g., 0x284a  


Question 9  
What is the total packet length (in bytes) of each packet of this beacon? e.g., 15  
74 B

Question 10  
Which IOC is found but is not a beacon destination? e.g., domain.com  


Question 11  
What is the beacon IOC that is contained in the pcap? e.g., domain.com  
![Alt text](image.png)  
gobreach.com  
`Get-Content .\apturls.txt | ForEach-Object { select-string -path .\resolved_urls.txt -Pattern $_ }`  


Question 12  
What is the IP address associated with IOC beacon?  
gobroadreach.com  

Question 13  
What is the relative start time of the first beacon (rounded to the nearest second)?  
__174 seconds__  
74 seconds  
154 seconds  
15 seconds  


Question 14  
What is the interval of the beacon?  
5 minutes  
1 minute  
2 minutes  
10 minutes  


Question 15  
What is the length of the TCP beacon conversations (in KB)?  


Question 16  
How many packets are involved in the communication to this beacon?  


Question 17  
How many packets were sent to this beacon?  


Question 18  
In the whole recorded network activity, how many kilobytes were exchanged between the recording machine and the beacon?  
288 KB  

## Exercise 4-1-4 Deploy GRR Agent  
---

** Remote Deployment of GRR will be on the exam **

[GRR Rapid Response Documentation](https://grr-doc.readthedocs.io/en/latest/)  
[Windows Remote Management](https://learn.microsoft.com/en-us/windows/win32/winrm/portal?redirectedfrom=MSDN)  
[PSExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)  

__Scenario__  

Having completed collection activities with any datasets and capabilities that are native in the network, it is time to deploy CPT capability onto specific hosts. The threat in question has recently started using the wdboot.sys file for DLL hijacking, and you must verify this file has not been affected.  

__Action Summary__  

Deploy a GRR client to the Windows Server target using PowerShell.  
`1..100 | % {"172.16.12.$($_): $(Test-Connection -count 1 -comp 172.16.12.$($_) -quiet)"}`  
Ensure PS Remoting is enabled!  
`Set-NetConnectionProfile -NetworkCategory private`  
`Enable-PSRemoting`  
`winrm quickconfig`  
`Set-Item wsman:\localhost\client\trustedhosts -Value *`  

`Copy-Item -Path \\serverb\c$\programs\temp\test.txt -Destination \\servera\c$\programs\temp\test.txt;`  
Once the item has been transferred, we must execute it.  


`Enter-PSSession -UseSSL -ComputerName 172.16.12.6 -Credential Administrator`  
Verify you have deployed the GRR client by collecting information with flows.   
Answer questions pertaining to this exercise.   

```
$Session = New-PSSession -ComputerName "Server01" -Credential "Contoso\User01"   
Copy-Item "D:\Folder001\test.log" -Destination "C:\Folder001_Copy\" -ToSession $Session
```

Question 1  
What is the kernel version of the Windows Server Client?  

Note: If you are having trouble please re-read the introduction to understand what you should have already completed!  
"OS Version" on the clients page of GRR has this info.  

Question 2  
On the Server Client, what is the last four characters of the MD5 hash for the file wdboot.sys?  


Question 3  
On the Server Client, what is the size of the hosts file?  


Question 4  
On the Server Client, what is the only added username on the remote system?  

Note: If GRR doesn't work use PowerShell Net Users.  
hsolo  

## Exercise 4-1-5 Create a Powershell Script to Collect Data from Multiple Systems  

__Scenario__

Your team has been tasked with searching the network for given IOCs for Windows Machines. You have been given a subnet you are authorized to access and a network map. However, network maps can be outdated, so you will verify for yourself what machines are available on the network.  

Create a PowerShell script that determines machines on the network that can be connected to, and then gathers registry keys, files, and network locations based on given IOCs. Your script should then alert the user to what machines have matching IOCs, and what the matching IOCs are. Your area of operations is 10.10.10.0/24.  

[Invoke-Command](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-5.1)  
[About Arrays](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_arrays?view=powershell-5.1)  

Pseudocode -  
Scan net for active hosts.  
Apply live hosts into list.  
Enumerate list using invoke-command  

```
# 1..255 | % { $a = $_; 135 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.$a",$_)) "10.10.10.$a"} 2>$null}

$computers = "10.10.10.56","10.10.10.83","10.10.10.107"
$creds = Get-Credential
#echo $computers


Invoke-Command  -ComputerName $computers -ScriptBlock {get-date} -Credential $creds

```  
![Alt text](image-2.png)
```
$port = 3389  
$network = "10.10.10"  
$range = 1..254  
$ErrorActionPreference= 'silentlycontinue'  
$(ForEach ($add in $range)
{ $ip = "{0}.{1}" -F $network.$add
write-progress "Scanning network" $ip -PercentCompelte (($add/$range.Count)*100)  
If(Test-Connection -BufferSize 32 -Count 1 -quiet -ComputerName $ip)  
{ $socket = new=object System.Net.Sockets.TcpClient($ip, $port)
If($socket.Connected) { "$ip port $port open"  
$socket.Close() }
}
Else { "$ip port $port not open " }  
})

```
![Alt text](image-1.png)

Question 1  
List the File IOCs detected for each Host discovered.  
iexplore.exe, adobeupdater


![Alt text](image-3.png)
Question 2  
What registry key value data matches the registry IOC list?  


Question 3  
What IP-based IOC finding is present on an end point?  


## Exercise 4-2-6 Identify Data Exfiltration Artifacts on a Windows System  
---

[List of File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)  
[Alternate Data Streams](https://learn.microsoft.com/en-us/archive/blogs/askcore/alternate-data-streams-in-ntfs)  
[Check File Headers with PowerShell](http://learningpcs.blogspot.com/2012/07/powershell-v3-check-file-headers.html)  
[PowerShell Get-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-5.1)  
[Using Get-Content to Hex Dump a File](https://www.itprotoday.com/powershell/get-hex-dumps-files-powershell)  


__Scenario__

You are tracking down a series of indicators that may relate to data exfiltration. There are no additional tools authorized for deployment; however, the system you are analyzing has PowerShell.



__Action Summary__

Use documentation from the resources section as needed.
Collect information from a system using PowerShell and analyze the data in search of potential exfil data.  


__SCENARIO 1__

Within the user's document directory, there is a folder called exercise_8.  

Your first task is to write a PowerShell script to search for all files that have a .ZIP or .RAR extension in the C:\Documents\exercise_8 directory.  

`Get-ChildItem -Filter *.zip -Recurse -ErrorAction SilentlyContinue -Force | Measure-Object`  

Question 1  
How many files within that directory (and subdirectories) have either a .ZIP or .RAR extension?  
126 zip + 135 rar = 261  

__Scenario 2__

At a quick glance, these documents appear benign. However, threat actors have been known to use Alternate Data Streams (ADS) to hide files.  

Modify the previous PowerShell script or write another script to identify which files within the "Exercise 8" directory have an ADS.  

`Get-Item * -stream * | Where-Object {$_.stream -ne ':$DATA'}`  - this showed every stream for every file, including standard ones. to find ADS I just looked for ones that the stream name wasn't $DATA  
`Get-Content -Path c:\Documents\exercise_8\file.txt -stream nameofstream`  

YOU DIDN'T LOOK IN SUBDIRECTORIES YOU IDIOT  

Question 2   
How many files had an ADS?   

```
PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\DCI
                Student\Documents\exercise_8\sgtcpqbwzo\pqyuemditc.txt:teoycsrwul
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\DCI Student\Documents\exercise_8\sgtcpqbwzo
PSChildName   : pqyuemditc.txt:teoycsrwul
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\DCI Student\Documents\exercise_8\sgtcpqbwzo\pqyuemditc.txt
Stream        : teoycsrwul
Length        : 384  
```
```
PS C:\Users\DCI Student\Documents\exercise_8\sgtcpqbwzo> get-content .\pqyuemditc.txt -stream teoycsrwul
PK   O†MKÎ´’Þ   a     ex8_pwdump.txt…Ð1N1…á‰»Øq;é(€ÙŽ#F‚ÝÕÎ,âøD[ÒPºð§_ïi|m§m?®zœ¯½ ôŒª‚b“ŠCp"ÁÈŽœ# ZGiu€4
Q"Y„ÏÄÍ“ƒ$ÓþPK?    O†MKÎ´’Þ   a   $               ex8_pwdump.txt
         <gáædDÓ;ûïW™CÓ3ÔèW™CÓPK      `

```


Question 3  
What are the names of the files that contain the ADS?  
ADS1:     
ADS2:   pqyuemditc.txt:teoycsrwul  
ADS3:   wfzardupoq.txt:mltjcfwgbx


Question 4  
What are the last 4 digits of the SHA1 for each file?  
ADS1:   
ADS2:   2DD188745678440424D8666E513E19FD6493C463  
ADS3:   


__Scenario 3__  

Extract the ADS into files and use PowerShell to determine the file signature of each file.   

Question 5  
What type of file was extracted from ADS1 (ibdlcsoznj.txt -> swogrxkcbh)?  


Question 6  
Are you able to access the content of the file extracted from ADS1?  
Yes  
__No__  


Question 7  
What type of file was extracted from ADS2 (pqyuemditc.txt - > teoycsrwul)?  
Zip file masquerading as a text file. I believe it to be ex8_pwdump.txt    

Question 8  
What was the content of the file extracted from ADS2?  


Question 9  
What type of file was extracted from ADS3?  


Question 10  
What was the content of the file extracted from ADS3?  




```
Get-Content ".\pqyuemditc.txt" -Encoding Byte `
  -ReadCount 16 | ForEach-Object {
  $output = ""
  foreach ( $byte in $_ ) {
#BEGIN CALLOUT A
    $output += "{0:X2} " -f $byte
#END CALLOUT A
  }
  $output
}
6F 73 65 70 6E 61 78 66 69 64 67 79 76 6C 72 0D
0A
```
```
PS C:\Users\DCI Student\Documents\exercise_8\sgtcpqbwzo> 
>> Get-Content ".\pqyuemditc.txt" -Encoding Byte `
>>   -ReadCount 16 -stream teoycsrwul | ForEach-Object {
>>   $output = ""
>>   foreach ( $byte in $_ ) {
>> #BEGIN CALLOUT A
>>     $output += "{0:X2} " -f $byte
>> #END CALLOUT A
>>   }
>>   $output
>> }
50 4B 03 04 14 00 00 00 08 00 4F 86 4D 4B CE B4
92 05 DE 00 00 00 61 01 00 00 0E 00 00 00 65 78
38 5F 70 77 64 75 6D 70 2E 74 78 74 85 D0 31 4E
04 31 0C 85 E1 1E 89 BB D8 71 12 3B E9 28 10 07
80 1E D9 8E 23 46 82 DD D5 CE 2C E2 F8 44 5B D2
50 BA F0 A7 5F EF 69 7C 6D A7 6D 3F AE 7A 9C AF
BD 00 F4 8C AA 82 62 05 93 8A 43 70 22 C1 C8 8E
  +  +   +   +   +   +   +   +   +   +   +  +
```
^ 50 4B is PK  

Question 11  
Another issue to consider is whether we missed any other ZIP or RAR files during our initial search. Modify your PowerShell searches to identify the file signature of all the files we have found, including those within an ADS. How many TXT files have a file signature that does not imply it is a text file?

15 files.

`Get-Content *.txt`  

## 4-2-7 Identify Keylogger Artifacts on a Windows System
---

__Scenario__

In this exercise, you will use Windows PowerShell to search for files that may have been created by a keylogger. PowerShell will prove useful, as most environments use Windows operating systems heavily. Students will also be using GRR to search for other log files that have been created by the suspected keylogger.

__Action Summary__

- Create a PowerShell script to search Windows systems for the keylogger tool used by APT1.
- Modify the PowerShell script to collect the log data associated with the keylogger.
- Use GRR to find files created around the time of the keylogger's creation date/time.
- Use GRR to collect registry keys created around the time of the keylogger's creation date/time.
- Record your findings.
- Answer questions within the exercise.

[PowerShell Get-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-5.1)   
[APT1 Documentation](https://malware.lu/assets/files/articles/RAP002_APT1_Technical_backstage.1.0.pdf)  
```
KeyX.exe 3d0760bbc1b8c0bc14e8510a66bf6d99 Keylogger, log in %APPDATA%/
teeamware.log
```
[GRR Documentation](https://grr-doc.readthedocs.io/en/latest/)  


Question 1  
Where was the currently running keylogger found on the system?  

NOTE: Base your answer on the name of the file, not the hash.  
Verify we are talking about KeyX.exe, the keylogger listed in the APT1 Docs, by running `Get-Process`  
`Get-ChildItem -Path C:\ -Filter KeyX.exe -Recurse -ErrorAction SilentlyContinue -Force`  
`Get-CimInstance -ClassName win32_process | where Name -like KeyX* | select *`  
```
PS C:\Users\DCI Student> get-childitem -path c:\ -filter KeyX.exe -recurse -erroraction silentlycontinue -force

    Directory: C:\Users\DCI Student\AppData\Local

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         1/3/2018   6:06 PM        4738538 KeyX.exe

    Directory: C:\Windows

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         1/3/2018   6:06 PM        4738538 KeyX.exe
```
Question 2  
What additional log file was created around the same time as teeamware.log?  
```
PS C:\Users\DCI Student> get-childitem -path c:\ -filter teeamware.log -recurse -erroraction silentlycontinue -force | select name,creationtime

Name          CreationTime
----          ------------
teeamware.log 1/3/2018 6:08:10 PM
```
`Get-ChildItem -path c:\ -recurse -erroraction silentlycontinue -filter *.log -force | select fullname,creationtime | Where-Object { $_.CreationTime -ge "1/2/2018" -and $_.CreationTime -le "1/4/2018" }`   
```
FullName                                                       CreationTime
--------                                                       ------------
C:\Users\DCI Student\AppData\Local\Microsoft\advkey.log        1/3/2018 6:08:10 PM
C:\Users\DCI Student\AppData\Roaming\teeamware.log             1/3/2018 6:08:10 PM
```



Question 3  
Using full path, where was the additional log file from Question 2 located on the system?   
__C:\Users\DCI Student\AppData\Local\Microsoft\advkey.log__

Question 4  
What is the value name of the entry found in the associated registry run key?
`Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`  

```
PS C:\Users\DCI Student> Get-Item -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

    Hive: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion

Name                           Property
----                           --------
Run                            OneDrive        : "C:\Users\DCI Student\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
                               Keyboard Driver : C:\Windows\KeyX.exe
```



## Exercise 4-2-8 Understand a Possible Phishing Attempt  * * *

__Scenario__  

Sometimes, systems are pulled back for forensics when a potential compromise is detected. The analysis of that host system can vary depending on the depth of the situation. In this exercise, there is a concern that one of the hosts has been compromised. The local defenders have obtained traffic from when it was believed to have happened and files from the system. They are handing off the items to you for further analysis. Students will use these files in the Exercise folder located on the Windows NAS. 

__Action Summary__

Analyze suspicious traffic from a host.  
Use NetworkMiner to view network traffic.  
Conduct analysis on artifacts found on a system.  


__Files List:__

Suspicious Files  
1.zip  
image.bmp  
NetworkMiner_2-3-2.zip  
QS12Setup.exe  
suspicious traffic.pcap  


[Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)  
[NetworkMiner](https://www.netresec.com/docs/NetworkMiner_Manual.pdf)  
[QuickStego](http://www.quickcrypto.com/free-steganography-software.html)  

Question 1  
What percentage of traffic is DNS?  
`udp.port == 53 && !icmp`  
Statistics > Protocol Heirarchy (with no active filter)  
__69.5%__  
31.5%  
40%  
33%  


Question 2  
There is no SMTP traffic.  
True  
__False__  

Question 3  
What percentage of the traffic is SMTP?

__0.2%__  
5%  
3%  
0.6%  

Question 4  
What domain name looks suspicious from the SMTP traffic?  
rocketmail.com  

Question 5  
What user’s email address is found in traffic that responded to the suspicious domain?  
kelly[@]voterdb.com  

Question 6  
What is the subject of the emails?  
Press Release

Question 7  
What is the name of the email attachment from the suspicious domain?    
Follow TCP stream > 

Question 8  
If you follow the TCP stream, what type of encoding is used by SMTP for the contents of the zip file?  
__Base64__  
UTF-8  
Quoted-printable   
No encoding  
```
------=_=-_OpenGroupware_org_NGMime-3125-1539108025.806621-19------
Content-Type: multipart/alternative;  boundary="----=_=-_OpenGroupware_org_NGMime-3125-1539108025.806472-18------"  

------=_=-_OpenGroupware_org_NGMime-3125-1539108025.806472-18------
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable
Content-Length: 573
```

Question 9  
You are unable to carve out the attachment using Wireshark.  
Find the packet with the bytes - copy them directly out. OR use network miner.  
True  
__False__  


Question 10  
Locate the .zip file in Network Miner and get the MD5 hash of the zip file. What are the last four characters?   

Question 11  
What is the size of the zip file?   


Question 12  
When was the last write time (MM/DD/YY HH:MM AM/PM)?    


Question 13  
Extract the .zip file using Network Miner. What is the filename of the document within the zip file?   


Question 14  
After analyzing the file, what does this file attempt to do?   


Question 15  
Use the supplied image.bmp file located in Suspicious Files. Did the password from the image open the password-protected file, 1.zip (also located in Suspicious Files)?  
True  
False  

Question 16  
Review the output from QuickStego. What necessary steps should be taken to obtain the real password?  


Question 17  
After looking at the password-protected file, what information was gathered from the host?   






## Ex 4-2-9-15  Assess Potentially Compromised Hosts
---

Scenario

The potentially compromised hosts you are investigating in this scenario are 10.10.10.7 through 10.10.10.13.

Username: Administrator  
Password: N@n0S3rveP@ssw0rd  


Questions in this exercise ask about the following areas of attacker activity:  

–  Data collected by the attacker  
–  Command and Control IP addresses and domain names 
–  Unauthorized access to credentials  
–  Attempted and/or successful privilege escalation  
–  Attempts by the adversary to evade discovery and remediation  
–  Activities performed to discover other potential targets on the network  
–  Any executables the adversary ran during their operation  
–  Successful or actual lateral movements performed by the adversary  
–  Methods of persistence used  
–  A full accounting of any malware left on the system  


Use your operator logs to document your process and findings. You should attempt the essays after your analysis.  
```
$computers = "10.10.10.7","10.10.10.8","10.10.10.9,10.10.10.10","10.10.10.11","10.10.10.12","10.10.10.13"
$creds = Get-Credential
#echo $computers

Invoke-Command  -ComputerName $computers -ScriptBlock {COMMAND} -Credential $creds

Individual commands run on hosts:  
Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  
Get-Item -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  
Get-ChildItem -Path C:\ -Filter <filename for IOC> -Recurse -ErrorAction SilentlyContinue -Force
cat c:\Windows\System32\Drivers\etc\hosts  
get-scheduledtask -taskname <IOC task>  
cat c:\tmp\sys.txt < this was an enumeration results file - did they add guest to administrators? >
```

Action Summary

Use host and network sensor capabilities to assess the state of a system.  
Identify actions performed post-compromise.  
Identify indicators of compromise and the threat agent likely responsible.  


---

Question 1  
Using the IOC list, what data or files on the systems were targeted and/or collected by the attacker?

sys.txt - enumeration file


Question 2  
What data or files could be considered IOCs but were not listed on the IOC list? Why do you consider them IOCs?




Question 3  
What potentially malicious IP addresses and domain names were used in this attack?

loads. listed in notepad.  
178.105.226.163			   uae.kim  
148.212.247.185			   updato.systes.net  
201.70.116.57				   removalmalware.servecounterstrike.com  
93.212.59.21				   mailchat.zapto.org  
outlookscansafe.net			
uae.kim					
updato.systes.net			
removalmalware.servecounterstrike.com	
mailchat.zapto.org			

Question 4  
Did the attacker successfully escalate privileges?

I believe so, adding a malicious account to administrator group. Also added guest to admin group on 3 boxes.  


Question 5  
What actions did the adversary take to ensure continued access in the event of discovery and remediation?  
Scheduled task



Question 6  
What activities did the attacker perform to discover other potential targets on the network?
queried shares



Question 7  
Were any executables run by the adversary during their operation? What were they? What do they do?




Question 8  
Is there any evidence of lateral movement or attempts to move laterally through the network?
definitive, no. circumstantial, yes  



Question 9  
What methods of persistence were used by the adversary?  
Scheduled tasks



Question 10  
What malware is present on the system? What do you think it does?  

```
# N@n0S3rveP@ssw0rd
Start-Transcript -path "C:\users\dci student\desktop\output3.txt" -append
$network = "10.10.10"  
$host_range=7..13  
$targets = New-Object System.Collections.ArrayList  
$creds= Get-Credential  
$files = "c:\users\DCI Student\desktop\aptfiles.txt"  

#test host connectivity. will only establish pssessions with active hosts
ForEach ($i in $host_range)  
{
  $ip="{0}.{1}" -F $network,$i
  if (Test-Connection -BufferSize 32 -count 1 -quiet -computername $ip)
  {
    echo "$ip is alive!"
    $targets.Add($ip)
  }
}

#begin connections and surveys

foreach ($item in $targets)  
{
  $sess = New-PSSession -ComputerName $item -Credential $creds
  copy-item -tosession $sess -Path $files -destination "c:\"
  invoke-command -computername $item -credential $creds -command {
  $f = get-content c:\aptfiles.txt
  foreach ($l in $f){
  echo "searching for $l on $item"
    get-childitem -path c:\ -force -filter $l -recurse -erroraction silentlycontinue  | select fullname,directory
    }
  }
}
stop-transcript
```


`ipconfig /displaydns`  
get DNS cache ^  



## Mod 4 Exam  
---
IOC list are located in the EOM content zip folder. EOM password: Mod4FinalP@ssw0rd  
Only ONE of the computers has ANY IOCs to find on it  
For question one you'll use pcap netplan.sh in /usr/local/bin (SO sensor)  
 
sudo tcpreplay -i eth0 -M 10 /usr/local/bin/netplan.sh &


Question 1  
After implementing the updated sensor placement plan (SPP) and monitoring the network, what network IOC associated with APT28 was identified?  

``` 
A DNS request from 172.29.234.51 for "www.biocpl.org" is located - C&C server for APT28. DNS server responds with "93.184.215.200". After this DNS query, an HTTPS session opens with this IP from internal IP 172.29.234.47.     

Towards the end of the capture, we see internal IP 172.29.234.37 send a DNS query for domain "www.virusdefender.org", another IOC for this APT. This DNS reply is 104.171.117.216. No further traffic was seen related to this IP or domain.  
```

Question 2  
Reporting IOC and Next Actions  

You have reported your findings up the chain of command. It was de-conflicted with the CTE team in order to confirm it is malicious. The CTE team stated it wasn't them. The Supported Command has been briefed of the active intrusion into their network. The CND Manager has delegated the Pre-Approved Actions to other members of the Squad so that they can isolate, contain and analyze the compromise. The CND Manager wants you to continue to monitor the network to identify any other suspicious or malicious activity. APT28’s end state is to compromise and exfiltrate information from database servers.

Update IOCs  

The DCI intelligence analyst has received a Cyber Activity Report (CAR) from NTOC that details new IOCs that should be immediately implemented concerning APT28.  

Note: Sensor Placement C was selected due to environment restrictions. You will still be able to monitor effectively with the sensor placed in this location.  

Which server has suspicious network activity?  

```
Only two IPs on the netmap are alive - only one is able to connect to. We will work from there, 172.16.8.9.  
```
__Analyze a Host System__

Perform host analysis of the Windows Server remotely using the Windows 10 CPT box.  

Note 1: If GRR isn't working, please use PowerShell and the SysInternals suite. We recommend using those tools instead of GRR for this portion of the test (hint, hint).   

Note 2: The SysInternals suite is in the Resources Drive in the "other" folder. Make sure to extract to the desktop.   

Note 3: Copy, Install/Run the applications needed to the server from the Windows 10 machine.   

Note 4: APT28 IOC list is in the Resources Drive in the "EOM" Folder then in the MOD4 Exam Folder. The password is Mod4FinalP@ssw0rd.  

```
alive hosts:  
172.16.8.5 - can't successfully RDP 
172.16.8.9 - what are the creds? Administrator\P@ssw0rd
```


Question 3  
After performing analysis on the suspected host, what malicious registry key is associated with APT28 activity identified previously?   
`HCKU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN\LastEnum = %SYSTEMROOT%\hpinst.exe`  


Question 4  
After performing analysis on the suspected host, what malicious executable, associated with APT28 activity, was identified?  
```
FullName       : C:\Documents and Settings\Administrator\Downloads\hpinst.exe
Directory      : C:\Documents and Settings\Administrator\Downloads
PSComputerName : 172.16.8.9
RunspaceId     : 25c9d3c8-4af0-4436-b276-3f5922aef15f

FullName       : C:\Users\Administrator\Downloads\hpinst.exe
Directory      : C:\Users\Administrator\Downloads
PSComputerName : 172.16.8.9
RunspaceId     : 25c9d3c8-4af0-4436-b276-3f5922aef15f

FullName       : C:\Windows\hpinst.exe
Directory      : C:\Windows
PSComputerName : 172.16.8.9
RunspaceId     : 25c9d3c8-4af0-4436-b276-3f5922aef15f
```

Question 5  
After performing analysis on the suspected host, what DLL file associated with APT28 activity was identified?  
```
FullName       : C:\Windows\apisvcd.dll
Directory      : C:\Windows
PSComputerName : 172.16.8.9
RunspaceId     : 25c9d3c8-4af0-4436-b276-3f5922aef15f
```

Question 6  
After performing analysis on the suspected host, which memory object (mutex) was identified?  

hpinst is PID 3336
```
C:\>handle -a -p 3336 | findstr /c:Mutant
  2A4: Mutant        \Sessions\1\BaseNamedObjects\sSbydFdIob6NrhNTJcF89uDqE2
```


ASijnoKGszdpodPPiaoaghj8127391   
ASLIiasiuqpssuqkl713h  
513AbTAsEpcq4mf6TEacB  
__sSbydFdIob6NrhNTJcF89uDqE2__  
B5a20F03e6445A6987f8EC87913c9  

Question 7  
Identify and Report Exfil Artifacts  

What findings uncovered during your analysis should be coordinated or reported to other elements within your CPT? Detail these findings here and identify to what CPT mission element they should be reported. Identify and report exfil artifacts.  

hpinst.exe and apisvcd.dll have the same file hash. This hash is not listed in the IOC malware. I recommend getting a malware analyst to crack open this file in a sandbox and see how it works, it could be something new. I took a look at strings but was in over my head, but I did see what could've been signs of host enumeration and exfiltration. I also identified the following information:
```
icmpBeacon
37.220.176.69i
Password: P@ssw0rdi
```

172.16.8.9 has an attempted HTTPS connection to the IP annotated in the CAR (37.220.176.69). I would like a network analyst to look further into this connection and see if any prior connections have occurred.  

I would like a host/net analyst duo to dig into the internal IP annotated in the CAR and see if they can find which direction the movement occurred. Who was infected first?   