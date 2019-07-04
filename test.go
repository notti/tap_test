package main

import (
	"fmt"
	"log"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

func htons(data uint16) uint16 { return data<<8 | data>>8 }

type matcher struct {
	packets map[string]int
	seen    map[int]int
	lock    sync.Mutex
}

func makeMatcher(packets map[string]int) *matcher {
	return &matcher{
		packets: packets,
		seen:    make(map[int]int, len(packets)),
	}
}

func (m *matcher) reset() map[int]int {
	m.lock.Lock()
	defer m.lock.Unlock()
	ret := make(map[int]int, len(m.seen))
	for key, value := range m.seen {
		ret[key] = value
	}
	for key := range m.seen {
		delete(m.seen, key)
	}
	return ret
}

func (m *matcher) received(packet []byte) error {
	i, ok := m.packets[string(packet)]
	if !ok {
		return fmt.Errorf("received unknown packet: %s", gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default).Dump())
	}
	m.lock.Lock()
	m.seen[i] = m.seen[i] + 1
	m.lock.Unlock()
	return nil
}

type tester struct {
	tapFD, socketFD   int
	gotTap, gotSocket *matcher
}

func makeTester(tapFD int, name string, packets [][]byte) (*tester, error) {
	socketFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("couldn't open packet socket: %s", err)
	}

	intf, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("couldn't query interface %s: %s", name, err)
	}

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  intf.Index,
	}

	if err := unix.Bind(socketFD, &addr); err != nil {
		return nil, fmt.Errorf("couldn't bind to interface %s: %s", name, err)
	}

	pmap := make(map[string]int, len(packets))

	for i, packet := range packets {
		pmap[string(packet)] = i
	}

	ret := tester{
		tapFD:     tapFD,
		socketFD:  socketFD,
		gotTap:    makeMatcher(pmap),
		gotSocket: makeMatcher(pmap),
	}

	go func() {
		packet := make([]byte, 4096)
		for {
			n, err := unix.Read(tapFD, packet)
			if err != nil {
				log.Fatal("tap read failed: ", err)
			}
			decoded := gopacket.NewPacket(packet[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
			if nl := decoded.NetworkLayer(); nl != nil && nl.LayerType() == layers.LayerTypeIPv6 {
				continue
			}
			if err := ret.gotTap.received(packet[:n]); err != nil {
				log.Fatal("tap: ", err)
			}
		}
	}()

	handle, err := pcapgo.NewEthernetHandle(name)
	if err != nil {
		return nil, fmt.Errorf("couldn't open tap-network-device: %s", err)
	}

	go func() {
		for {
			packet, _, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				log.Fatal("error reading packet from tap-network-device")
			}
			decoded := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.NoCopy)
			if nl := decoded.NetworkLayer(); nl != nil && nl.LayerType() == layers.LayerTypeIPv6 {
				continue
			}
			if err := ret.gotSocket.received(packet); err != nil {
				log.Fatal("netdev: ", err)
			}
		}
	}()

	return &ret, nil
}

func (t *tester) writeTap(packet []byte) error {
	_, err := unix.Write(t.tapFD, packet)
	return err
}

func (t *tester) writeSocket(packet []byte) error {
	_, err := unix.Write(t.socketFD, packet)
	return err
}

func (t *tester) expect(tap, socket map[int]int) error {
	gotTap := t.gotTap.reset()
	gotSocket := t.gotSocket.reset()
	if !reflect.DeepEqual(gotTap, tap) {
		return fmt.Errorf("tap: expected %#v but got %#v", tap, gotTap)
	}
	if !reflect.DeepEqual(gotSocket, socket) {
		return fmt.Errorf("socket: expected %#v but got %#v", socket, gotSocket)
	}
	return nil
}

type expect struct {
	tap, socket map[int]int
}

type rwtest struct {
	packets       [][]byte
	receive, send expect
	desc          string
}

func (rw rwtest) run(t *tester) {
	log.Printf("[%s] Testing tap send...\n", rw.desc)

	for _, p := range rw.packets {
		t.writeTap(p)
	}

	time.Sleep(1 * time.Second)

	if err := t.expect(rw.send.tap, rw.send.socket); err != nil {
		log.Fatal(err)
	}

	log.Printf("[%s] Testing tap recieve...\n", rw.desc)

	for _, p := range rw.packets {
		t.writeSocket(p)
	}

	time.Sleep(1 * time.Second)

	if err := t.expect(rw.receive.tap, rw.receive.socket); err != nil {
		log.Fatal(err)
	}
}
