wiping linux drive

```dc3dd wipe=/dev/nvme1n1p1 tpat="Media wiped on 20230727 by Caleb McLean"```  

```dc3dd wipe=/dev/nvme1n1p1 pat=12345678```



```xxd -s 45983 -l 1 /dev/nvme1n1p1 <- this specific byte```


```xxd -l 512 (first 512 bytes)```

```xxd -l 45983 /dev/nvme1n1p1```

```fdisk -l "/dev/sda"```

`fdisk -l`  

(still doesn't show IR Drive by name, it's the one at the top tho)

GParted to partition drive?
GUI tool on Kali.
- start by selecting drive in top right
- device - > create partition table -> select type: xxx -> apply
- partition -> create new partition -> can edit file size, system
- free space following - SET TO 0!
- hit add