package main

import (
    "encoding/binary"
    "strings"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "time"
    "net"
    "bytes"
    "context"
)


func listenMDNS(ctx context.Context) {
    handle, err := pcap.OpenLive(iface, 1024, false, 10 * time.Second)
    if err != nil {
        log.Fatal("pcap打开失败:", err)
    }
    defer handle.Close()
    handle.SetBPFFilter("udp and port 5353")
    ps := gopacket.NewPacketSource(handle, handle.LinkType())
    for {
        select {
        case <- ctx.Done():
            return
        case p := <-ps.Packets():
            if len(p.Layers()) == 4 {
                c := p.Layers()[3].LayerContents()
                if c[2] == 0x84 && c[3] == 0x00 && c[6] == 0x00 && c[7] == 0x01{
                    // 从网络层(ipv4)拿IP, 不考虑IPv6
                    i := p.Layer(layers.LayerTypeIPv4)
                    if i == nil {
                        continue
                    }
                    ipv4 := i.(*layers.IPv4)
                    ip := ipv4.SrcIP.String()
                    // 把 hostname 存入到数据库
                    h := ParseMdns(c)
                    if len(h) > 0 {
                        pushData(ip, nil, h, "")
                    }
                }
            }
        }
    }
}

// 根据ip生成含mdns请求包，包存储在 buffer里
func mdns(buffer *Buffer, ip string) {
    b := buffer.PrependBytes(12)
    binary.BigEndian.PutUint16(b, uint16(0)) // 0x0000 标识
    binary.BigEndian.PutUint16(b[2:], uint16(0x0100)) // 标识
    binary.BigEndian.PutUint16(b[4:], uint16(1)) // 问题数
    binary.BigEndian.PutUint16(b[6:], uint16(0)) // 资源数
    binary.BigEndian.PutUint16(b[8:], uint16(0)) // 授权资源记录数
    binary.BigEndian.PutUint16(b[10:], uint16(0)) // 额外资源记录数
    // 查询问题
    ipList := strings.Split(ip, ".")
    for j := len(ipList) - 1; j >= 0; j-- {
        ip := ipList[j]
        b = buffer.PrependBytes(len(ip) + 1)
        b[0] = uint8(len(ip))
        for i := 0; i < len(ip); i++ {
            b[i + 1] = uint8(ip[i])
        }
    }
    b = buffer.PrependBytes(8)
    b[0] = 7 // 后续总字节
    copy(b[1:], []byte{'i', 'n', '-', 'a', 'd', 'd', 'r'})
    b = buffer.PrependBytes(5)
    b[0] = 4 // 后续总字节
    copy(b[1:], []byte{'a', 'r', 'p', 'a'})
    b = buffer.PrependBytes(1)
    // terminator
    b[0] = 0
    // type 和 classIn
    b = buffer.PrependBytes(4)
    binary.BigEndian.PutUint16(b, uint16(12))
    binary.BigEndian.PutUint16(b[2:], 1)
}

func sendMdns(ip IP, mhaddr net.HardwareAddr) {
    srcIp := net.ParseIP(ipNet.IP.String()).To4()
    dstIp := net.ParseIP(ip.String()).To4()
    ether := &layers.Ethernet{
        SrcMAC: localHaddr,
        DstMAC: mhaddr,
        EthernetType: layers.EthernetTypeIPv4,
    }
    
    ip4 := &layers.IPv4{
        Version: uint8(4),
        IHL: uint8(5),
        TTL: uint8(255),
        Protocol: layers.IPProtocolUDP,
        SrcIP: srcIp,
        DstIP: dstIp,
    }
    bf := NewBuffer()
    mdns(bf, ip.String())
    udpPayload := bf.data
    udp := &layers.UDP{
        SrcPort: layers.UDPPort(60666),
        DstPort: layers.UDPPort(5353),
    }
    udp.SetNetworkLayerForChecksum(ip4)
    udp.Payload = udpPayload  // todo
    buffer := gopacket.NewSerializeBuffer()
    opt := gopacket.SerializeOptions{
        FixLengths: true,       // 自动计算长度
        ComputeChecksums: true, // 自动计算checksum
    }
    err := gopacket.SerializeLayers(buffer, opt, ether, ip4, udp, gopacket.Payload(udpPayload))
    if err != nil {
        log.Fatal("Serialize layers出现问题:", err)
    }
    outgoingPacket := buffer.Bytes()
    
    handle, err := pcap.OpenLive(iface, 1024, false, 10 * time.Second)
    if err != nil {
        log.Fatal("pcap打开失败:", err)
    }
    defer handle.Close()
    err = handle.WritePacketData(outgoingPacket)
    if err != nil {
        log.Fatal("发送udp数据包失败..")
    }
}

// 参数data  开头是 dns的协议头 0x0000 0x8400 0x0000 0x0001(ans) 0x0000 0x0000
// 从 mdns响应报文中获取主机名
func ParseMdns(data []byte) string {
    var buf bytes.Buffer
    i := bytes.Index(data, []byte{0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00})
    if i < 0 {
        return ""
    }
    
    for s := i - 1; s > 1; s-- {
        num := i - s
        if s - 2 < 0 {
            break
        }
        // 包括 .local_ 7 个字符
        if bto16([]byte{data[s - 2], data[s - 1]}) == uint16(num + 7) {
            return Reverse(buf.String())
        }
        buf.WriteByte(data[s])
    }
    
    return ""
}

func bto16(b []byte) uint16 {
    if len(b) != 2 {
        log.Fatal("b只能是2个字节")
    }
    return uint16(b[0]) << 8 + uint16(b[1])
}


