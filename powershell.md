### Powershell
---
Today we take our first look at powershell.  

[Threat Hunting with PS](https://www.sans.org/white-papers/38842/)  
[Script Examples](https://learn.microsoft.com/en-us/powershell/scripting/samples/sample-scripts-for-administration?view=powershell-7.3&viewFallbackFrom=powershell-7)  

#### Establishing remote connection with Powershell
---
[ps-session documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.3&viewFallbackFrom=powershell-6)  

Ensure PS Remoting is enabled!  
`Enable-PSRemoting`  
`winrm quickconfig`  
`Set-NetConnectionProfile -NetworkCategory private`  


Ping Sweep for net enumeration example:  
`1..20 | % {"10.10.10.$($_): $(Test-Connection -count 1 -comp 10.10.10.$($_) -quiet)"}`  
```
>> 1..10 | % {"10.10.10.$($_): $(Test-Connection -count 1 -comp 10.10.10.$($_) -quiet)"}
10.10.10.1: False
10.10.10.2: True
10.10.10.3: True
10.10.10.4: True
10.10.10.5: True
10.10.10.6: False
10.10.10.7: True
10.10.10.8: False
10.10.10.9: False
10.10.10.10: False
```
Ensure to update the trusted hosts file!  
`Set-Item wsman:\localhost\client\trustedhosts -Value *`

Once we ID our target machine using the ping TTL (windows in 128), we can remotely connect using the following command (CAN NOT BE RUN IN ADMIN PS SESSION):  
`Enter-PSSession -UseSSL -ComputerName 10.10.10.40 -Credential "DCI Student"`

Now we can start the exercise... two and a half hours later...  


Registry Queries:  
`Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`  

User Enumeration:  
`Get-LocalUser`  
`gwmi win32_UserAccount`  

Scheduled Tasks:  
`Get-ScheduledTasks`  
`Get-ScheduledTaskInfo`  

Disk Information:  
`Gwmi Win32_LogicalDisk`  

Net Connections:  
`Get-NetTCPConnection`  

Event Logs:  
`Get-EventLog -LogName System -Newest 100`  
`Get-EventLog -LogName System -InstanceID 414 -Newest 100`  

