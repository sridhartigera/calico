// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ut_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestCtExpiryWithICMP(t *testing.T) {
	RegisterTestingT(t)

        defer func() { bpfIfaceName = "" }()
        bpfIfaceName = "REC1"

        resetCTMap(ctMap) // ensure it is clean

	icmpEcho := makeICMPEcho(srcIP, node1ip, 8 /* Echo Request*/)

        hostIP = node1ip

        // Insert a reverse route for the source workload.
        rtKey := routes.NewKey(srcV4CIDR).AsBytes()
        rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err := rtMap.Update(rtKey, rtVal)
        Expect(err).NotTo(HaveOccurred())
	ctTimeouts := timeouts.DefaultTimeouts()
	ctTimeouts.ICMPTimeout = 1 * time.Second
	skbMark = 0
        runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
                res, err := bpfrun(icmpEcho)
                Expect(err).NotTo(HaveOccurred())
                Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
                pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
                fmt.Printf("pktR = %+v\n", pktR)
        }, withConntrackTimeouts(ctTimeouts))
        expectMark(tcdefs.MarkSeen)
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))
	var (
		ctKey conntrack.Key
		ctVal conntrack.Value
	)

	for ctKey, ctVal = range ct {
		// Get the only k,v in the map
	}

	v := ctVal.Data()
	// Set the seqno, which isn't applicable for UDP.
	v.A2B.Seqno = 1234
	ctVal.SetLegA2B(v.A2B)

	_ = ctMap.Update(ctKey.AsBytes(), ctVal.AsBytes())
	time.Sleep(1100 * time.Millisecond)
	skbMark = 0
        runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
                res, err := bpfrun(icmpEcho)
                Expect(err).NotTo(HaveOccurred())
                Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
                pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
                fmt.Printf("pktR = %+v\n", pktR)
        }, withConntrackTimeouts(ctTimeouts))
        expectMark(tcdefs.MarkSeen)
	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))
	for ctKey, ctVal = range ct {
		// Get the only k,v in the map
	}
	v = ctVal.Data()
	// Though seq num is not applicable for UDP. Setting this previously helps us
	// ensure if the entry that we are seeing is the new one as the previous one
	// has expired.
	Expect(v.A2B.Seqno).To(Equal(uint32(0)))
}

func TestCtExpiryWithUDP(t *testing.T) {
	RegisterTestingT(t)

        defer func() { bpfIfaceName = "" }()
        bpfIfaceName = "REC1"

        resetCTMap(ctMap) // ensure it is clean

        _, _, _, _, pktBytes, err := testPacketUDPDefault()
        Expect(err).NotTo(HaveOccurred())

        hostIP = node1ip

        // Insert a reverse route for the source workload.
        rtKey := routes.NewKey(srcV4CIDR).AsBytes()
        rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
        err = rtMap.Update(rtKey, rtVal)
        Expect(err).NotTo(HaveOccurred())
	ctTimeouts := timeouts.DefaultTimeouts()
	ctTimeouts.UDPTimeout = 1 * time.Second
	skbMark = 0
        runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
                res, err := bpfrun(pktBytes)
                Expect(err).NotTo(HaveOccurred())
                Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
                pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
                fmt.Printf("pktR = %+v\n", pktR)
        }, withConntrackTimeouts(ctTimeouts))
        expectMark(tcdefs.MarkSeen)
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))
	var (
		ctKey conntrack.Key
		ctVal conntrack.Value
	)

	for ctKey, ctVal = range ct {
		// Get the only k,v in the map
	}

	v := ctVal.Data()
	// Set the seqno, which isn't applicable for UDP.
	v.A2B.Seqno = 1234
	ctVal.SetLegA2B(v.A2B)

	_ = ctMap.Update(ctKey.AsBytes(), ctVal.AsBytes())
	time.Sleep(1100 * time.Millisecond)
	skbMark = 0
        runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
                res, err := bpfrun(pktBytes)
                Expect(err).NotTo(HaveOccurred())
                Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
                pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
                fmt.Printf("pktR = %+v\n", pktR)
        }, withConntrackTimeouts(ctTimeouts))
        expectMark(tcdefs.MarkSeen)
	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))
	for ctKey, ctVal = range ct {
		// Get the only k,v in the map
	}
	v = ctVal.Data()
	// Though seq num is not applicable for UDP. Setting this previously helps us
	// ensure if the entry that we are seeing is the new one as the previous one
	// has expired.
	Expect(v.A2B.Seqno).To(Equal(uint32(0)))
}

func TestCtExpiryWithTCPSynSent(t *testing.T) {
	RegisterTestingT(t)

	defer func() { bpfIfaceName = "" }()
	bpfIfaceName = "REC1"

	resetCTMap(ctMap) // ensure it is clean

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, _, _, _, synPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	ctTimeouts := timeouts.DefaultTimeouts()
	ctTimeouts.TCPSynSent = 1 * time.Second
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	}, withConntrackTimeouts(ctTimeouts))
	expectMark(tcdefs.MarkSeen)

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))

	// Wait for a second for conntrack to expire
	time.Sleep(1100 * time.Millisecond)
	tcpMid := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		DataOffset: 5,
	}
	skbMark = 0
	_, _, _, _, midPkt, err := testPacketV4(nil, nil, tcpMid, nil)
	Expect(err).NotTo(HaveOccurred())
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(midPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	}, withConntrackTimeouts(ctTimeouts))

	// Expect the CT entry to be deleted as it expired.
	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(0))
}

func TestCtExpiryWithTCPFinsSeen(t *testing.T) {
	RegisterTestingT(t)

	defer func() { bpfIfaceName = "" }()
	bpfIfaceName = "REC1"

	resetCTMap(ctMap) // ensure it is clean

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, _, _, _, synPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	ctTimeouts := timeouts.DefaultTimeouts()
	ctTimeouts.TCPFinsSeen = 1 * time.Second
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	}, withConntrackTimeouts(ctTimeouts))
	expectMark(tcdefs.MarkSeen)

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))

	var (
		ctKey conntrack.Key
		ctVal conntrack.Value
	)

	for ctKey, ctVal = range ct {
		// Get the only k,v in the map
	}

	v := ctVal.Data()
	v.A2B.SynSeen = true
	v.A2B.FinSeen = true
	v.A2B.Opener = true
	ctVal.SetLegA2B(v.A2B)
	v.B2A.FinSeen = true
	v.B2A.AckSeen = true
	v.B2A.Opener = true
	ctVal.SetLegB2A(v.B2A)

	_ = ctMap.Update(ctKey.AsBytes(), ctVal.AsBytes())
	// Wait for a second for conntrack to expire
	time.Sleep(1100 * time.Millisecond)
	tcpMid := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		DataOffset: 5,
	}
	skbMark = 0
	_, _, _, _, midPkt, err := testPacketV4(nil, nil, tcpMid, nil)
	Expect(err).NotTo(HaveOccurred())
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(midPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	}, withConntrackTimeouts(ctTimeouts))

	// Expect the CT entry to be deleted as it expired.
	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(0))
}

func TestCtExpiryWithTCPRstSeen(t *testing.T) {
	RegisterTestingT(t)

	defer func() { bpfIfaceName = "" }()
	bpfIfaceName = "REC1"

	resetCTMap(ctMap) // ensure it is clean

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, _, _, _, synPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	ctTimeouts := timeouts.DefaultTimeouts()
	ctTimeouts.TCPResetSeen = 1 * time.Second
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	}, withConntrackTimeouts(ctTimeouts))
	expectMark(tcdefs.MarkSeen)

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))

	var (
		ctKey conntrack.Key
		ctVal conntrack.Value
	)

	for ctKey, ctVal = range ct {
		// Get the only k,v in the map
	}

	v := ctVal.Data()
	v.A2B.SynSeen = true
	v.A2B.RstSeen = true
	v.A2B.Opener = true
	ctVal.SetLegA2B(v.A2B)

	_ = ctMap.Update(ctKey.AsBytes(), ctVal.AsBytes())
	// Wait for a second for conntrack to expire
	time.Sleep(1100 * time.Millisecond)
	tcpMid := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		DataOffset: 5,
	}
	skbMark = 0
	_, _, _, _, midPkt, err := testPacketV4(nil, nil, tcpMid, nil)
	Expect(err).NotTo(HaveOccurred())
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(midPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	}, withConntrackTimeouts(ctTimeouts))

	// Expect the CT entry to be deleted as it expired.
	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(0))
}

func TestCtExpiryWithTCPEstablished(t *testing.T) {
	RegisterTestingT(t)

	defer func() { bpfIfaceName = "" }()
	bpfIfaceName = "REC1"

	resetCTMap(ctMap) // ensure it is clean

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, _, _, _, synPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	ctTimeouts := timeouts.DefaultTimeouts()
	ctTimeouts.TCPEstablished = 1 * time.Second
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	}, withConntrackTimeouts(ctTimeouts))
	expectMark(tcdefs.MarkSeen)

	// Set the ct to ESTABLISHED
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))

	var (
		ctKey conntrack.Key
		ctVal conntrack.Value
	)

	for ctKey, ctVal = range ct {
		// Get the only k,v in the map
	}

	v := ctVal.Data()
	v.A2B.SynSeen = true
	v.A2B.AckSeen = true
	v.A2B.Opener = true
	ctVal.SetLegA2B(v.A2B)
	v.B2A.SynSeen = true
	v.B2A.AckSeen = true
	v.B2A.Opener = true
	ctVal.SetLegB2A(v.B2A)

	Expect(v.Established()).To(BeTrue())
	_ = ctMap.Update(ctKey.AsBytes(), ctVal.AsBytes())
	// Wait for a second for conntrack to expire
	time.Sleep(1100 * time.Millisecond)
	tcpMid := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		DataOffset: 5,
	}
	skbMark = 0
	_, _, _, _, midPkt, err := testPacketV4(nil, nil, tcpMid, nil)
	Expect(err).NotTo(HaveOccurred())
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(midPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	}, withConntrackTimeouts(ctTimeouts))

	// Expect the CT entry to be deleted as it expired.
	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(0))
}
