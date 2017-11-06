# goscan

![image](https://user-images.githubusercontent.com/1621058/32154543-63c4e560-bcff-11e7-8a92-5281e18f221e.png)

**特点：**
 * 扫描整个内网IPv4空间
 * 向整个内网发送ARP包
 * 显示IP/MAC地址/主机名/设备厂商名
 * 利用SMB(Windows)和mDNS(Mac OS)嗅探内网主机名(hostname)
 * 利用MAC地址计算设备的厂商信息
 
 更多细节可以查看 [用Go开发可以内网活跃主机嗅探器](https://github.com/timest/goscan/issues/1)
 
**Features:**
 * Scan the whole IPv4 address space
 * Scan your local network with ARP packets
 * Display the IP address, MAC address, hostname and vendor associated
 * Using SMB(Windows devices) and mDNS(Apple devices) to detect hostname
 
 
### Usage: ###

```go
$ go build main
$ sudo ./main  
or 
$ sudo ./main -I en0
```

Goscan must run as **root**.

Goscan work in Linux/Mac using [libpcap](http://www.tcpdump.org/) and on Windows with [WinPcap](https://www.winpcap.org/install/). 

If you need English comments, check this fork: https://github.com/skoky/goscan/tree/english 

