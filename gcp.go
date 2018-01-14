package main

import  (
	"fmt"
	"github.com/google/gopacket/pcap"
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
		//fmt.Println(dev_idx, dev.Name, dev.Addresses[0].IP, dev.Addresses[0].Netmask)

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
}
