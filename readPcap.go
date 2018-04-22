package main

// Use tcpdump to create a test file
// tcpdump -w output.pcap
// then read with this program

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
        // "os"
)

var (
	pcapFile = "output.pcap" // or os.Args[1] make sure to uncomment impor os
	handle   *pcap.Handle
	err	error
)

func main() {
     // Open file instead of device
     handle, err = pcap.OpenOffline(pcapFile)
     if err != nil {
	log.Fatal(err)
     }

     defer handle.Close()

     // Loop through packets in file
     packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
     for packet   := range packetSource.Packets() {
		fmt.Println(packet)
     }

} // end of main
