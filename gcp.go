package main

import  (
	"fmt"
	"time"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"bufio"
	"os"
	"strconv"
	"strings"
	"github.com/olekukonko/tablewriter"
)

func main() {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"SNO", "Device Name", "Device IP", "Device Netmask"})

	var devs []pcap.Interface
	devs, _  = pcap.FindAllDevs()
	for temp, dev := range devs {
		dev_idx := temp/2
		if len(dev.Addresses) == 0 {
			continue
		}
		table.Append([]string{strconv.Itoa(dev_idx), string(dev.Name), dev.Addresses[0].IP.String(), dev.Addresses[0].Netmask.String()})

	}

	table.Render()

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\nPlease Enter Ethernet Device SNO: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSuffix(input,"\n")
	udev_idx, _ := strconv.ParseInt(input, 10, 64)
	udev_idx = 2*udev_idx

	udev := devs[int(udev_idx)]
	fmt.Println("Chosen device is: ", udev.Name)

	var device string = string(udev.Name)
	var snapshot int32 = 65535
	var promiscuous bool = false
	var timeout time.Duration = -1 * time.Second
	var handle *pcap.Handle
	handle, _ = pcap.OpenLive(device,snapshot, promiscuous, timeout)
	defer handle.Close()

	reader = bufio.NewReader(os.Stdin)
        fmt.Println("\nDo you wish to see L3 packets, L4 packets, both L3/L4 packets simultaneously or set a filter? Please enter your choice/SNO: ")

	tableMenu := tablewriter.NewWriter(os.Stdout)
	tableMenu.SetHeader([]string{"SNO", "Option"})
	tableMenu.Append([]string{"0", "Only Layer 3"})
	tableMenu.Append([]string{"1", "Only Layer 4"})
	tableMenu.Append([]string{"2", "Both Layer 3 and Layer 4"})
	tableMenu.Append([]string{"3", "Apply Filter (Per packet output)"})
	tableMenu.Render()

	fmt.Println("Enter your choice: ")
	choice_input, _ := reader.ReadString('\n')
        choice_input = strings.TrimSuffix(choice_input,"\n")
	choice, _ := strconv.ParseInt(choice_input, 10, 64)
	ip_bool, tcp_bool, filter_bool := 0,0,0
	if choice == 0 {
		ip_bool = 1
	} else if choice == 1 {
		tcp_bool = 1
	} else if choice == 2 {
		ip_bool = 1
		tcp_bool = 1
	} else if choice == 3 {
		filter_bool = 1
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("\nPlease enter filter: ")
		filter, _ := reader.ReadString('\n')
		filter = strings.TrimSuffix(filter, "\n") 
		err := handle.SetBPFFilter(filter)
		if err == nil {
			fmt.Println("[INFO] Filter applied successfully!")
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {

		if filter_bool == 1 {
			fmt.Println(packet)
		}

		tableIP := tablewriter.NewWriter(os.Stdout)
        	tableIP.SetHeader([]string{"IP Protocol", "Source IP", "Destination IP"}) 
		tableTCP := tablewriter.NewWriter(os.Stdout)
                tableTCP.SetHeader([]string{"TCP ACK", "TCP SYN", "Source Port", "Destination Port"})

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer != nil {
			ip, _ := ipv4Layer.(*layers.IPv4)
			tableIP.Append([]string{ip.Protocol.String(), ip.SrcIP.String(), ip.DstIP.String()})
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			tableTCP.Append([]string{strconv.FormatBool(tcp.ACK), strconv.FormatBool(tcp.SYN), tcp.SrcPort.String(), tcp.DstPort.String()}) 
		}

		if ip_bool == 1 && ipv4Layer != nil {
			tableIP.Render()
		}

		if tcp_bool == 1 && tcpLayer != nil {
			tableTCP.Render()
		}
	}
}
