
### GRRRRRRR ( GRR Rapid Response )
---
[GRR Documentation](https://grr-doc.readthedocs.io/en/latest/)

server  = root/toor (?)  
web ui = dcistudent/P@ssw0rd

After logging in to the GRR server, verify IP address using ip a.  
```
root@grr-server:~# ip a

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 02:f5:e4:c7:d1:6b brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.4/22 brd 10.10.11.255 scope global ens5
       valid_lft forever preferred_lft forever
    inet6 fe80::f5:e4ff:fec7:d16b/64 scope link 
       valid_lft forever preferred_lft forever
```

Once we have the IP address, we can make the configuration changes to the /etc/grr/server.local.yaml file.  
```
vi /etc/grr/server.local.yaml
1 AdminUI.url: http://10.10.10.4:8000
*   *   *   *   *   *   *   *   *   *   *   *   *   *   *
88 Client.server_urls: http://10.10.10.4:8080/
```
Ensure the IP in the lines above is the IP of the GRR server!

If you change the GRR server IP address in the yaml, you must reconfigure the GRR agents by repacking them with the new information in the server.local.yaml file and then push them back out to the clients.
```
grr_config_updater repack_clients
```

After running all these commands, you should be able to connect to the GRR Web UI from our Windows 10 box using the creds listed above.

Once connected, follow the file flow on the left to install and deploy the local agent.  
Manage binaries -> Executables -> Windows -> Installers - Select and download GRR_3.1.0.2_amd64.exe -> Show file location -> run as administrator

Next, hit the spyglass next to search box - we should see host data here! Now we can use the GUI to make our queries against host data. 

And now the GRR server is configured and we can successfully deploy and view agent information!


---
### Threat Hunting with GRR

#### File Path Examples  

All executables or dlls in each user’s download directory:  
`%%users.homedir%%\Downloads\*.{exe,dll}`

All .evtx files found up to three directories under C:\Windows\System32\winevt”:  

`%%environ_systemroot%%\System32\winevt\**.evtx`

“findme.txt” iles in user homedirs, up to 10 directories deep:

`%%users.homedir%%/**10/findme.txt`

Query REG keys

Start new flow -> Registry -> Registry Finder  
Here you can specify paths just like the file system. Don't use the CollectRunKeyBinaries flow!  

Using Rekall

To use Rekall, we need to work within memory. So select "Memory" under the start new flow menu.

AnalyzeClientMemory -> Plugins -> type 'pslist' in the box here. This will literally just run a process list. 

For a list of the Rekall plugins available, check 
[here](https://rekall.readthedocs.io/en/latest/plugins.html).  
Notable plugins include pslist, users, object_tree.   

With the object_tree plugin, we can add regex arguments I guess?

type_regex = "Mutant"










