package main

import (
    "net"
    "github.com/Sirupsen/logrus"
    "time"
    "fmt"
    "sync"
    "sort"
    "context"
    "os"
    "strings"
    manuf "github.com/timest/gomanuf"
)

var log = logrus.New()
// ipNet 存放 IP地址和子网掩码
var ipNet *net.IPNet
// 本机的mac地址，发以太网包需要用到
var localHaddr net.HardwareAddr
// 存放最终的数据，key[string] 存放的是IP地址
var data map[string]Info
// 计时器，在一段时间没有新的数据写入data中，退出程序，反之重置计时器
var t *time.Ticker
var do chan string

const (
    iface = "en0"
    // 3秒的计时器
    START = "start"
    END = "end"
)

type Info struct {
    // IP地址
    Mac      net.HardwareAddr
    // 主机名
    Hostname string
    // 厂商信息
    Manuf    string
}

// 格式化输出结果
// xxx.xxx.xxx.xxx  xx:xx:xx:xx:xx:xx  hostname  manuf
// xxx.xxx.xxx.xxx  xx:xx:xx:xx:xx:xx  hostname  manuf
func PrintData() {
    var keys IPSlice
    for k := range data {
        keys = append(keys, ParseIPString(k))
    }
    sort.Sort(keys)
    for _, k := range keys {
        d := data[k.String()]
        mac := ""
        if d.Mac != nil {
            mac = d.Mac.String()
        }
        fmt.Printf("%-15s %-17s %-30s %-10s", k.String(), mac, d.Hostname, d.Manuf)
        fmt.Println()
    }
}

// 将抓到的数据集加入到data中，同时重置计时器
func pushData(ip string, mac net.HardwareAddr, hostname, manuf string) {
    // 停止计时器
    do <- START
    var mu sync.RWMutex
    mu.RLock()
    defer func() {
        // 重置计时器
        do <- END
        mu.RUnlock()
    }()
    if _, ok := data[ip]; !ok {
        data[ip] = Info{Mac: mac, Hostname: hostname, Manuf: manuf}
        //log.Info("入库ip:", ip)
        return
    }
    info := data[ip]
    if len(hostname) > 0 && len(info.Hostname) == 0 {
        info.Hostname = hostname
    }
    if len(manuf) > 0 && len(info.Manuf) == 0 {
        info.Manuf = manuf
    }
    if mac != nil {
        info.Mac = mac
    }
    data[ip] = info
}

func init() {
    // 初始化data
    data = make(map[string]Info)
    do = make(chan string)
    // 获取网卡信息（ip和子网掩码) 和 Mac地址信息
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        log.Fatal("无法获取本地网络信息:", err)
    }
    for i, a := range addrs {
        if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() {
            if ip.IP.To4() != nil {
                ipNet = ip
                it, err := net.InterfaceByIndex(i)
                if err != nil {
                    log.Fatal("无法获取当前网络信息")
                }
                localHaddr = it.HardwareAddr
                break
            }
        }
    }
    if ipNet == nil {
        log.Fatal("无法获取本地网络信息")
    }
}

func localHost() {
    host, _ := os.Hostname()
    data[ipNet.IP.String()] = Info{Mac: localHaddr, Hostname: strings.TrimSuffix(host, ".local"), Manuf: manuf.Search(localHaddr.String())}
}

func sendARP() {
    // ips 是内网IP地址集合
    ips := Table(ipNet)
    for _, ip := range ips {
        go sendArpPackage(ip)
    }
}

func main() {
    localHost()
    ctx, cancel := context.WithCancel(context.Background())
    go listenARP(ctx)
    go listenMDNS(ctx)
    go listenNBNS(ctx)
    go sendARP()
    
    t = time.NewTicker(4 * time.Second)
    for {
        select {
        case <-t.C:
            PrintData()
            cancel()
            goto END
        case d := <-do:
            switch d {
            case START:
                t.Stop()
            case END:
                // 接收到新数据，重置2秒的计数器
                t = time.NewTicker(2 * time.Second)
            }
        }
    }
    END:
    
}

