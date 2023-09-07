### Powershell
---
Today we take our first look at powershell.  

[Threat Hunting with PS](https://www.sans.org/white-papers/38842/)  
[Script Examples](https://learn.microsoft.com/en-us/powershell/scripting/samples/sample-scripts-for-administration?view=powershell-7.3&viewFallbackFrom=powershell-7)  

#### Establishing remote connection with Powershell
---
[ps-session documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.3&viewFallbackFrom=powershell-6)  

Ensure PS Remoting is enabled!  
`Set-NetConnectionProfile -NetworkCategory private`  
`Enable-PSRemoting`  
`winrm quickconfig`  
`Set-Item wsman:\localhost\client\trustedhosts -Value *`  

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

** Note - no quotes around single word names. UseSSL not always required. Send connection request from a non-admin box!  

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

For-each loop to compare files  
`Get-Content .\apturls.txt | ForEach-Object { select-string -path .\resolved_urls.txt -Pattern $_ }`  

```
$port = (443)
$network = “192.168.13.”
$range = 1..254
$ErrorActionPreference= ‘silentlycontinue’
$(Foreach ($add in $range)
{ $ip = “{0}.{1}” –F $network,$add
Write-Progress “Scanning Network” $ip -PercentComplete (($add/$range.Count)*100)
If(Test-Connection –BufferSize 32 –Count 1 –quiet –ComputerName $ip)
{ $socket = new-object System.Net.Sockets.TcpClient($ip, $port)
If($socket.Connected) { “$ip port $port open”
$socket.Close() }
else { “$ip port $port not open ” }
}
}) | Out-File C:\reports\portscan.csv
```

** note the "TcpClient" field in the script! Ensure to update when scanning for UDP ports!  

```
$ipRangeStart = "192.168.13.19"
$ipRangeEnd = "192.168.13.40"
$port = 1434

$ipRangeStartParts = $ipRangeStart.Split('.')
$ipRangeEndParts = $ipRangeEnd.Split('.')

for ($i = [int]$ipRangeStartParts[3]; $i -le [int]$ipRangeEndParts[3]; $i++) {
    $ipToCheck = "{0}.{1}.{2}.{3}" -f $ipRangeStartParts[0], $ipRangeStartParts[1], $ipRangeStartParts[2], $i
    $ipEndPoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($ipToCheck), $port)
    $tcpClient = New-Object System.Net.Sockets.TcpClient

    try {
        $tcpClient.Connect($ipEndPoint)
        Write-Host "Port $port is open on $ipToCheck"
    } catch {
        Write-Host "Port $port is closed on $ipToCheck"
    } finally {
        $tcpClient.Close()
    }
}
```

`Get-ChildItem -Path <path> -Filter <filename> -Recurse -ErrorAction SilentlyContinue -Force`  

Get files modified recently (last day)  
`Get-ChildItem -path c:\ -recurse -erroraction silentlycontinue -force | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}`