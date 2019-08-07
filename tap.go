package main

import (
	"fmt"
	"log"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func bringUp(name string) error {
	/* Set device up - could also be done with netlink */
	sockfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("couldn't create control socket: %s", err)
	}
	defer unix.Close(sockfd)

	flags := unix.IFReqShort{
		Name: name,
	}

	err = unix.IoctlIFReq(sockfd, unix.SIOCGIFFLAGS, &flags)
	if err != nil {
		return fmt.Errorf("couldn't query if flags: %s", err)
	}

	flags.Short |= unix.IFF_UP

	err = unix.IoctlIFReq(sockfd, unix.SIOCSIFFLAGS, &flags)
	if err != nil {
		return fmt.Errorf("couldn't set if flags: %s", err)
	}
	return nil
}

func main() {
	// Let's try out a name that is way to long
	name := "testTapWithVeryLongName"

	// Step 1: Open tun device
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		log.Fatal("Coudln't open tun device: ", err)
	}
	defer unix.Close(fd)

	// Step 2: TUNSETIFF with either IFF_TAP or IFF_TUN
	//         Without IFF_NO_PI every packet is/has to be prepended with unix.TUNPI
	//         The returned name is the one the kernel actually used
	//         If this call succeeds, packets can be read with unix.Read from the fd and written with unix.Write to the fd (one full packet per call)
	flags := unix.IFReqShort{
		Name:  name,
		Short: unix.IFF_TAP | unix.IFF_NO_PI,
	}
	err = unix.IoctlIFReq(fd, unix.TUNSETIFF, &flags)
	if err != nil {
		log.Fatal("Couldn't create interface: ", err)
	}
	name = flags.Name
	log.Println("Real name:", name)

	// No need to set MAC address explicitely - but we try out here if it works
	addr := unix.IFReqSockaddr{
		Name: name,
	}
	addr.Addr.Family = unix.ARPHRD_ETHER // hw addresses use ARPHRD values in Family!
	copy(addr.Addr.Data[:], []int8{0, 1, 2, 3, 4, 5})

	err = unix.IoctlIFReq(fd, unix.SIOCSIFHWADDR, &addr)
	if err != nil {
		log.Fatal("Couldn't set hwaddr: ", err)
	}

	err = bringUp(name)

	if err != nil {
		log.Fatal("Error bringing up interface: ", err)
	}

	// See if setting the address worked...
	realaddr := unix.IFReqSockaddr{
		Name: name,
	}
	err = unix.IoctlIFReq(fd, unix.SIOCGIFHWADDR, &realaddr)
	if err != nil {
		log.Fatal("Couldn't get hwaddr: ", err)
	}

	if !reflect.DeepEqual(addr, realaddr) {
		log.Fatalf("Setting HW address didn't work. Tried %#v but got %#v!", addr, realaddr)
	}

	// Ok let's do some sending and receiving tests

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	eth := layers.Ethernet{
		SrcMAC:       []byte{0, 1, 2, 3, 4, 5},
		DstMAC:       []byte{0, 1, 2, 3, 4, 3},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		SrcIP:    []byte{191, 168, 0, 1},
		DstIP:    []byte{191, 168, 0, 2},
		Protocol: layers.IPProtocolUDP,
	}

	udp := layers.UDP{
		SrcPort: 1024,
		DstPort: 1024,
	}

	payload := gopacket.Payload{'H', 'e', 'l', 'l', 'o', ' ', 't', 'a', 'p'}

	udp.SetNetworkLayerForChecksum(&ip)

	gopacket.SerializeLayers(buf, opts,
		&eth,
		&ip,
		&udp,
		&payload,
	)
	p1 := buf.Bytes()

	buf = gopacket.NewSerializeBuffer()
	eth.DstMAC = []byte{0, 1, 2, 3, 4, 10}

	gopacket.SerializeLayers(buf, opts,
		&eth,
		&ip,
		&udp,
		&payload,
	)
	p2 := buf.Bytes()

	buf = gopacket.NewSerializeBuffer()
	payload = gopacket.Payload{'B', 'a', 'd', ' ', 'P', 'a', 'c', 'k', 'e', 't'}

	gopacket.SerializeLayers(buf, opts,
		&eth,
		&ip,
		&udp,
		&payload,
	)
	p3 := buf.Bytes()

	packets := [][]byte{p1, p2, p3}

	t, err := makeTester(fd, name, packets)
	if err != nil {
		log.Fatal("Couldn't build tester: ", err)
	}

	// socket should see all three packets for send and receive
	// tap should only see packets for receive
	rwtest{
		packets: packets,
		send:    expect{map[int]int{}, map[int]int{0: 1, 1: 1, 2: 1}},
		receive: expect{map[int]int{0: 1, 1: 1, 2: 1}, map[int]int{0: 1, 1: 1, 2: 1}},
		desc:    "unfiltered",
	}.run(t)

	// Let's try out TUNFilter
	filter := unix.TUNFilter{
		Addrs: [][]byte{
			{0, 1, 2, 3, 4, 1},
			{0, 1, 2, 3, 4, 2},
			{0, 1, 2, 3, 4, 3},
		},
		Mask: unix.TUN_FLT_ALLMULTI,
	}

	err = unix.IoctlSetTUNFilter(fd, unix.TUNSETTXFILTER, &filter)
	if err != nil {
		log.Fatal("Couldn't set filter: ", err)
	}

	// same as above - but the filter should get rid of packets 1, 2 (wrong mac)
	rwtest{
		packets: packets,
		send:    expect{map[int]int{}, map[int]int{0: 1, 1: 1, 2: 1}},
		receive: expect{map[int]int{0: 1}, map[int]int{0: 1, 1: 1, 2: 1}},
		desc:    "TXFILTER",
	}.run(t)

	filter.Addrs = nil

	// remove filter
	err = unix.IoctlSetTUNFilter(fd, unix.TUNSETTXFILTER, &filter)
	if err != nil {
		log.Fatal("Couldn't set filter: ", err)
	}

	// should be same result as original test
	rwtest{
		packets: packets,
		send:    expect{map[int]int{}, map[int]int{0: 1, 1: 1, 2: 1}},
		receive: expect{map[int]int{0: 1, 1: 1, 2: 1}, map[int]int{0: 1, 1: 1, 2: 1}},
		desc:    "unfiltered",
	}.run(t)

	// Try out simple bpf filter
	// This removes all packets that don't start with H in the payload (p3 starts with B!)
	var fprog unix.SockFprog
	instr, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadExtension{Num: bpf.ExtPayloadOffset},
		bpf.TAX{},
		bpf.LoadIndirect{Off: 0, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 'H', SkipTrue: 1},
		bpf.RetConstant{Val: 4096},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		log.Fatal("Error assembling bpf program")
	}
	fprog.Len = uint16(len(instr))
	rawprog := make([]unix.SockFilter, len(instr))
	for i := range instr {
		rawprog[i].Code = instr[i].Op
		rawprog[i].Jf = instr[i].Jf
		rawprog[i].Jt = instr[i].Jt
		rawprog[i].K = instr[i].K
	}
	fprog.Filter = &rawprog[0]

	err = unix.IoctlSetSockFprog(fd, unix.TUNATTACHFILTER, &fprog)
	if err != nil {
		log.Fatal("Couldn't attach filter: ", err)
	}

	testfprog, err := unix.IoctlGetSockFprog(fd, unix.TUNGETFILTER)
	if err != nil {
		log.Fatal("Couldn't load back filter: ", err)
	}

	if !reflect.DeepEqual(&fprog, testfprog) {
		log.Fatal("Read back BPF filter is not the same")
	}

	// Now only packet 2 shouldn't be received due to payload starting with B
	rwtest{
		packets: packets,
		send:    expect{map[int]int{}, map[int]int{0: 1, 1: 1, 2: 1}},
		receive: expect{map[int]int{0: 1, 1: 1}, map[int]int{0: 1, 1: 1, 2: 1}},
		desc:    "BPF",
	}.run(t)

	// remove bpf filter
	err = unix.IoctlSetInt(fd, unix.TUNDETACHFILTER, 0)
	if err != nil {
		log.Fatal("Couldn't detach filter: ", err)
	}

	// should be back to normal
	rwtest{
		packets: packets,
		send:    expect{map[int]int{}, map[int]int{0: 1, 1: 1, 2: 1}},
		receive: expect{map[int]int{0: 1, 1: 1, 2: 1}, map[int]int{0: 1, 1: 1, 2: 1}},
		desc:    "unfiltered",
	}.run(t)

	log.Println("Success!")
}
