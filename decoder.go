package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"log"
	"time"
	"strings"
)

var (
	device		  = "ens3"  // or eth0 or on macOS en0 
	snapshotLen int32 = 1024
	promiscuous	  = false
	err	    error
	timeout		  = 30 * time.Second
	handle		  *pcap.Handle
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
           log.Fatal(err)
	}

	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process here
		// fmt.Println(packet)
		printPacketInfo(packet)

	}

} // end of main

func printPacketInfo(packet gopacket.Packet) {

   // Let's see if the packet is an ethernet packet
   ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
   if ethernetLayer != nil {
	fmt.Println(">>>>>>>>>>>[  Ethenet layer detected ]<<<<<<<<<<<<<");
	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
        fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
	fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
	// Ethernet type is typically IPv4 but could be ARP or Other
        fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
	fmt.Println()
   }

   // Let's see if the packet is IP
   ipLayer := packet.Layer(layers.LayerTypeIPv4)
   if ipLayer != nil {
	fmt.Println("-=-=-=-=-=-=-=-_____  IPv4 layer detected  ____=-=-=-=-=-=-=-")
        ip, _ := ipLayer.(*layers.IPv4)

        // IP layer variables:
        // Version (Either 4 or 6 )
        // IHL (IP Header Length in 32-bit words)
        // TOS, Length, Id, Flags, FragOffset, TTL, Protocal (TCP?)
        // Checksum, SrcIP, DstIP
	fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
        fmt.Println("Protocol: ", ip.Protocol)
        fmt.Println()
   }

   // Let's see if the packet is TCP
   tcpLayer := packet.Layer(layers.LayerTypeTCP)
   if tcpLayer != nil {
	fmt.Println("+_+_+_+_+_+_+====  TCP layer detected ====+_+_+_+_+_+_+_+_")
        tcp, _ := tcpLayer.(*layers.TCP)

        // TCP layer variables:
        // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum
        // Urgent
        // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
        fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
        fmt.Println("Sequence number: ", tcp.Seq)
        fmt.Println()
   }


   // Iterate over all the layers printing out each layer type
   fmt.Println("All packet layers:")
   for _, layer := range packet.Layers() {
	fmt.Println("- " , layer.LayerType() )
   }

   // When iterating through packet.Layers() 
   // if it lists Payload layer then that is the same as
   // this applicationLayer. applicationLayer contains the payload
   applicationLayer := packet.ApplicationLayer()
   if applicationLayer != nil {
	fmt.Println(" [   Application layer/Payload found ]  ")
	fmt.Printf("%s\n", applicationLayer.Payload())

	// Search for a string inside the payload
	if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
	   fmt.Println("######_______   HTTP found  _______######")
	}
   }

   // Check for errors
   if err := packet.ErrorLayer(); err != nil {
	fmt.Println("Error decoding some part of the packet:", err)
   }

} // end of printPacketInfo


