// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/bpf/tc"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/bpf/xdp"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
)

var canTestMarks bool

func init() {
	logutils.ConfigureEarlyLogging()
	log.SetLevel(log.DebugLevel)

	fd := environment.NewFeatureDetector(make(map[string]string))
	if ok, err := fd.KernelIsAtLeast("5.9.0"); err == nil && ok {
		canTestMarks = true
	}
}

// Constants that are shared with the UT binaries that we build.
const (
	natTunnelMTU  = uint16(700)
	testVxlanPort = uint16(5665)
)

var (
	rulesDefaultAllow = &polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name:  "allow all",
				Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Allow"}}},
			}},
		}},
	}
	node1ip    = net.IPv4(10, 10, 0, 1).To4()
	node1ip2   = net.IPv4(10, 10, 2, 1).To4()
	node1tunIP = net.IPv4(11, 11, 0, 1).To4()
	node2ip    = net.IPv4(10, 10, 0, 2).To4()
	intfIP     = net.IPv4(10, 10, 0, 3).To4()
	node1CIDR  = net.IPNet{
		IP:   node1ip,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}
	node2CIDR = net.IPNet{
		IP:   node2ip,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}
)

// Globals that we use to configure the next test run.
var (
	hostIP       = node1ip
	skbMark      uint32
	bpfIfaceName string
)

const (
	resTC_ACT_OK int = iota
	resTC_ACT_RECLASSIFY
	resTC_ACT_SHOT
	resTC_ACT_PIPE
	resTC_ACT_STOLEN
	resTC_ACT_QUEUED
	resTC_ACT_REPEAT
	resTC_ACT_REDIRECT
	resTC_ACT_UNSPEC = (1 << 32) - 1
)

var retvalToStr = map[int]string{
	resTC_ACT_OK:         "TC_ACT_OK",
	resTC_ACT_RECLASSIFY: "TC_ACT_RECLASSIFY",
	resTC_ACT_SHOT:       "TC_ACT_SHOT",
	resTC_ACT_PIPE:       "TC_ACT_PIPE",
	resTC_ACT_STOLEN:     "TC_ACT_STOLEN",
	resTC_ACT_QUEUED:     "TC_ACT_QUEUED",
	resTC_ACT_REPEAT:     "TC_ACT_REPEAT",
	resTC_ACT_REDIRECT:   "TC_ACT_REDIRECT",
	resTC_ACT_UNSPEC:     "TC_ACT_UNSPEC",
}

const (
	resXDP_ABORTED int = iota
	resXDP_DROP
	resXDP_PASS
)

var retvalToStrXDP = map[int]string{
	resXDP_ABORTED: "XDP_ABORTED",
	resXDP_PASS:    "XDP_PASS",
	resXDP_DROP:    "XDP_DROP",
}

func expectMark(expect int) {
	if canTestMarks {
		ExpectWithOffset(1, skbMark).To(Equal(uint32(expect)),
			fmt.Sprintf("skbMark 0x%08x should be 0x%08x at %s", skbMark, expect, caller(2)))
	} else {
		// If we cannot verify the mark, set it to the expected value as the
		// next stage expects it to be set.
		skbMark = uint32(expect)
	}
}

func TestCompileTemplateRun(t *testing.T) {
	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", &polprog.Rules{}, func(bpfrun bpfProgRunFn) {
		_, _, _, _, pktBytes, err := testPacketUDPDefault()
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())

		// Implicitly denied by normal policy: DROP
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})
}

func TestLoadZeroProgram(t *testing.T) {
	RegisterTestingT(t)
	fd, err := bpf.LoadBPFProgramFromInsns(nil, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	if err == nil {
		_ = fd.Close()
	}
	Expect(err).To(Equal(unix.E2BIG))
}

type testLogger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
}

func startBPFLogging() *exec.Cmd {
	cmd := exec.Command("/usr/bin/bpftool", "prog", "tracelog")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		log.WithError(err).Warn("Failed to start bpf log collection")
		return nil
	}
	return cmd
}

func stopBPFLogging(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	err := cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		log.WithError(err).Warn("Failed to send SIGTERM to bpftool")
		return
	}
	err = cmd.Wait()
	if err != nil {
		log.WithError(err).Warn("Failed to wait for bpftool")
	}
}

func setupAndRun(logger testLogger, loglevel, section string, rules *polprog.Rules,
	runFn func(progName string), opts ...testOption) {
	topts := testOpts{
		subtests:  true,
		logLevel:  log.DebugLevel,
		psnaStart: 20000,
		psnatEnd:  30000,
	}

	for _, o := range opts {
		o(&topts)
	}

	tempDir, err := os.MkdirTemp("", "calico-bpf-")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir)

	err = os.Mkdir(bpfFsDir+"_v6", os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir + "v6")

	obj := "../../bpf-gpl/bin/test_xdp_debug"
	if !topts.xdp {
		obj = "../../bpf-gpl/bin/test_"
		if strings.Contains(section, "from") {
			obj += "from_"
		} else {
			obj += "to_"
		}

		if strings.Contains(section, "host") {
			obj += "hep_"
			topts.progLog = "HEP"
		} else if strings.Contains(section, "nat") {
			obj += "nat_"
			topts.progLog = "NAT"
		} else if strings.Contains(section, "wireguard") {
			obj += "wg_"
			topts.progLog = "WG"
		} else {
			obj += "wep_"
			topts.progLog = "WEP"
		}

		log.WithField("hostIP", hostIP).Info("Host IP")
		log.WithField("intfIP", intfIP).Info("Intf IP")
		obj += fmt.Sprintf("fib_%s", loglevel)

		if strings.Contains(section, "_dsr") {
			obj += "_dsr"
			// XXX bit of a hack, we should change the section names to contain _dsr
			section = strings.Trim(section, "_dsr")
		}
	}

	log.Infof("Patching binary %s", obj+".o")

	bin, err := bpf.BinaryFromFile(obj + ".o")
	Expect(err).NotTo(HaveOccurred())
	// XXX for now we both path the mark here and include it in the context as
	// well. This needs to be done for as long as we want to run the tests on
	// older kernels.
	bin.PatchSkbMark(skbMark)
	tempObj := tempDir + "bpf.o"
	err = bin.WriteToFile(tempObj)
	Expect(err).NotTo(HaveOccurred())

	o, err := objLoad(tempObj, bpfFsDir, "IPv4", topts, rules != nil, true)
	Expect(err).NotTo(HaveOccurred())
	defer o.Close()

	if topts.ipv6 {
		o, err := objLoad(obj+"_v6.o", bpfFsDir, "IPv6", topts, rules != nil, false)
		Expect(err).NotTo(HaveOccurred())
		defer o.Close()
	}

	if err != nil {
		logger.Log("Error:", string(err.(*exec.ExitError).Stderr))
	}
	Expect(err).NotTo(HaveOccurred())

	if rules != nil {
		alloc := &forceAllocator{alloc: idalloc.New()}
		ipsMapFD := ipsMap.MapFD()
		Expect(ipsMapFD).NotTo(BeZero())
		stateMapFD := stateMap.MapFD()
		Expect(stateMapFD).NotTo(BeZero())
		pg := polprog.NewBuilder(alloc, ipsMapFD, stateMapFD, jumpMap.MapFD(), false)
		insns, err := pg.Instructions(*rules)
		Expect(err).NotTo(HaveOccurred())
		var polProgFD bpf.ProgFD
		if topts.xdp {
			polProgFD, err = bpf.LoadBPFProgramFromInsns(insns, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_XDP)
		} else {
			polProgFD, err = bpf.LoadBPFProgramFromInsns(insns, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
		}
		Expect(err).NotTo(HaveOccurred(), "Failed to load rules program.")
		defer func() { _ = polProgFD.Close() }()
		err = jumpMapUpdate(jumpMap, tcdefs.ProgIndexPolicy, int(polProgFD))
		Expect(err).NotTo(HaveOccurred())
		log.WithField("rules", rules).Debug("set policy")
	}

	runFn(bpfFsDir + "/" + section)
}

func caller(skip int) string {
	_, f, l, ok := runtime.Caller(skip)
	if ok {
		return fmt.Sprintf("%s:%d", f, l)
	}

	return "<unknown>"
}

// runBpfTest runs a specific section of the entire bpf program in isolation
func runBpfTest(t *testing.T, section string, rules *polprog.Rules, testFn func(bpfProgRunFn), opts ...testOption) {
	RegisterTestingT(t)
	xdp := false
	if strings.Contains(section, "xdp") == false {
		section = "classifier_" + section
	} else {
		xdp = true
	}

	ctxIn := make([]byte, 18*4)
	binary.LittleEndian.PutUint32(ctxIn[2*4:3*4], skbMark)
	if xdp {
		// XDP tests cannot take context and would fail.
		ctxIn = nil
	}

	topts := testOpts{}

	for _, o := range opts {
		o(&topts)
	}

	cllr := caller(2)

	setupAndRun(t, "debug", section, rules, func(progName string) {
		label := section
		if topts.description != "" {
			label = topts.description + " - " + section
		}
		t.Run(label, func(_ *testing.T) {
			if strings.Contains(section, "calico_from_") {
				ExpectWithOffset(2, skbMark).To(Equal(uint32(0)),
					fmt.Sprintf("skb mark 0x%08x should be zero at %s", skbMark, cllr))
			}
			if !topts.hostNetworked && strings.Contains(section, "calico_to_") {
				ExpectWithOffset(2, skbMark&uint32(tcdefs.MarkSeen) != 0).
					To(BeTrue(), fmt.Sprintf("skb mark 0x%08x does not have tcdefs.MarkSeen 0x%08x set before tc at %s",
						skbMark, tcdefs.MarkSeen, cllr))
			}

			testFn(func(dataIn []byte) (bpfRunResult, error) {
				res, err := bpftoolProgRun(progName, dataIn, ctxIn)
				log.Debugf("dataIn  = %+v", dataIn)
				if err == nil {
					log.Debugf("dataOut = %+v", res.dataOut)
				}

				if res.Retval != resTC_ACT_SHOT && canTestMarks && strings.Contains(section, "calico_from_") {
					ExpectWithOffset(3, skbMark&uint32(tcdefs.MarkSeen) != 0).
						To(BeTrue(), fmt.Sprintf("skb mark 0x%08x does not have tcdefs.MarkSeen 0x%08x set after tc at %s",
							skbMark, tcdefs.MarkSeen, cllr))
				}

				return res, err
			})
		})
	}, opts...)
}

type forceAllocator struct {
	alloc *idalloc.IDAllocator
}

func (a *forceAllocator) GetNoAlloc(id string) uint64 {
	return a.alloc.GetOrAlloc(id)
}

func bpftool(args ...string) ([]byte, error) {
	args = append([]string{"--json", "--pretty"}, args...)
	cmd := exec.Command("bpftool", args...)
	log.WithField("cmd", cmd.String()).Debugf("executing")
	out, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			log.WithField("stderr", string(e.Stderr)).Errorf("bpftool %s failed: %v out=\n%v", args, err, string(out))
			// to make the output reflect the new lines, logrus ignores it
			fmt.Print(fmt.Sprint(string(e.Stderr)))
		}
	}

	return out, err
}

var (
	mapInitOnce sync.Once

	natMap, natBEMap, ctMap, rtMap, ipsMap, stateMap, testStateMap, jumpMap, affinityMap, arpMap, fsafeMap, countersMap, ifstateMap bpf.Map
	allMaps                                                                                                                         []bpf.Map
)

func initMapsOnce() {
	mapInitOnce.Do(func() {
		mc := &bpf.MapContext{}

		natMap = nat.FrontendMap(mc)
		natBEMap = nat.BackendMap(mc)
		ctMap = conntrack.Map(mc)
		rtMap = routes.Map(mc)
		ipsMap = ipsets.Map(mc)
		stateMap = state.Map(mc)
		testStateMap = state.MapForTest(mc)
		affinityMap = nat.AffinityMap(mc)
		arpMap = arp.Map(mc)
		fsafeMap = failsafes.Map(mc)
		countersMap = counters.MapForTest(mc)
		ifstateMap = ifstate.Map(mc)

		allMaps = []bpf.Map{natMap, natBEMap, ctMap, rtMap, ipsMap, stateMap, testStateMap,
			affinityMap, arpMap, fsafeMap, countersMap, ifstateMap}
		for _, m := range allMaps {
			err := m.EnsureExists()
			if err != nil {
				log.WithError(err).Panic("Failed to initialise maps")
			}
		}
	})
}

func cleanUpMaps() {
	log.Info("Cleaning up all maps")

	logLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	defer log.SetLevel(logLevel)

	for _, m := range allMaps {
		if m == stateMap || m == testStateMap || m == jumpMap || m == countersMap {
			continue // Can't clean up array maps
		}
		log.WithField("map", m.GetName()).Info("Cleaning")
		err := m.Iter(func(_, _ []byte) bpf.IteratorAction {
			return bpf.IterDelete
		})
		if err != nil {
			log.WithError(err).Panic("Failed to walk map")
		}
	}
	log.Info("Cleaned up all maps")
}

func jumpMapUpdatePinned(jm bpf.Map, idx int, val string) error {
	out, err := bpftool("map", "update", "pinned", jm.Path(),
		"key", fmt.Sprintf("%d", idx), "0", "0", "0", "value", "pinned", val)

	if err != nil {
		return fmt.Errorf("%s\n%w", string(out), err)
	}

	return nil
}

func jumpMapUpdate(jm bpf.Map, idx int, val int) error {
	var k, v [4]byte

	binary.LittleEndian.PutUint32(k[:], uint32(idx))
	binary.LittleEndian.PutUint32(v[:], uint32(val))

	return jm.Update(k[:], v[:])
}

func jumpMapDelete(jm bpf.Map, idx int) error {
	var k [4]byte

	binary.LittleEndian.PutUint32(k[:], uint32(idx))

	return jm.Delete(k[:])
}

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.LittleEndian.Uint32([]byte(ip[:]))
}

func objLoad(fname, bpfFsDir, ipFamily string, topts testOpts, polProg, hasHostConflictProg bool) (*libbpf.Obj, error) {
	log.WithField("program", fname).Debug("Loading BPF program")

	forXDP := topts.xdp

	jumpMap = jump.MapForTest(&bpf.MapContext{})
	if ipFamily == "IPv4" {
		// don't do for v6 as that requires v4 atm
		_ = unix.Unlink(jumpMap.Path())
	}
	err := jumpMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	obj, err := libbpf.OpenObject(fname)
	if err != nil {
		return nil, fmt.Errorf("open object %s: %w", fname, err)
	}

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		if m.IsMapInternal() {
			if forXDP {
				if err := xdp.ConfigureProgram(m, bpfIfaceName); err != nil {
					return nil, err
				}
			} else {
				ifaceLog := topts.progLog + "-" + bpfIfaceName
				globals := libbpf.TcGlobalData{
					HostIP:       ipToU32(hostIP),
					IntfIP:       ipToU32(intfIP),
					Tmtu:         natTunnelMTU,
					VxlanPort:    testVxlanPort,
					PSNatStart:   uint16(topts.psnaStart),
					PSNatLen:     uint16(topts.psnatEnd-topts.psnaStart) + 1,
					Flags:        1,
					HostTunnelIP: ipToU32(node1tunIP),
				}
				if err := tc.ConfigureProgram(m, ifaceLog, &globals); err != nil {
					return nil, fmt.Errorf("failed to configure tc program: %w", err)
				}
			}
			continue
		}
		pin := "/sys/fs/bpf/tc/globals/" + m.Name()
		log.WithField("pin", pin).Debug("Pinning map")
		cmd := exec.Command("bpftool", "map", "show", "pinned", pin)
		log.WithField("cmd", cmd.String()).Debugf("executing")
		out, _ := cmd.Output()
		log.WithField("output", string(out)).Debug("map")
		log.WithField("size", m.MaxEntries()).Debug("libbpf map")
		if err := m.SetPinPath(pin); err != nil {
			obj.Close()
			return nil, fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
	}

	if err := obj.Load(); err != nil {
		return nil, fmt.Errorf("load object: %w", err)
	}

	progDir := bpfFsDir
	policyIdx := tcdefs.ProgIndexPolicy

	if ipFamily == "IPv6" {
		progDir += "_v6"
		policyIdx = tcdefs.ProgIndexV6Policy
	}

	err = obj.PinPrograms(progDir)
	if err != nil {
		obj.Close()
		return nil, fmt.Errorf("pin %s programs to %s: %w", ipFamily, progDir, err)
	}

	if polProg {
		polProgPath := "xdp_policy"
		if !forXDP {
			polProgPath = "classifier_tc_policy"
		}
		polProgPath = path.Join(bpfFsDir, polProgPath)
		_, err = os.Stat(polProgPath)
		if err == nil {
			err = jumpMapUpdatePinned(jumpMap, policyIdx, polProgPath)
			if err != nil {
				err = errors.Wrap(err, "failed to update jump map (policy program)")
				goto out
			}
			log.Debug("set default policy")
		}
	}

	if !forXDP {
		err = tc.UpdateJumpMap(obj, tcdefs.JumpMapIndexes[ipFamily], false, hasHostConflictProg)
		if err != nil && !strings.Contains(err.Error(), "error updating calico_tc_host_ct_conflict program") {
			goto out
		}
		err = tc.UpdateJumpMap(obj, tcdefs.JumpMapIndexes[ipFamily], false, false)
	} else {
		if err := xdp.UpdateJumpMap(obj, xdp.JumpMapIndexes[ipFamily]); err != nil {
			goto out
		}
	}

out:
	if err != nil {
		_ = obj.UnpinPrograms(bpfFsDir)
		obj.Close()
		return nil, fmt.Errorf("%s: %w", ipFamily, err)
	}

	return obj, nil
}

type bpfRunResult struct {
	Retval   int
	Duration int
	dataOut  []byte
}

func (r bpfRunResult) RetvalStr() string {
	s := retvalToStr[r.Retval]
	if s == "" {
		return fmt.Sprint(r.Retval)
	}
	return s
}

func (r bpfRunResult) RetvalStrXDP() string {
	s := retvalToStrXDP[r.Retval]
	if s == "" {
		return fmt.Sprint(r.Retval)
	}
	return s
}

func bpftoolProgRun(progName string, dataIn, ctxIn []byte) (bpfRunResult, error) {
	return bpftoolProgRunN(progName, dataIn, ctxIn, 1)
}

func bpftoolProgRunN(progName string, dataIn, ctxIn []byte, N int) (bpfRunResult, error) {
	var res bpfRunResult

	tempDir, err := os.MkdirTemp("", "bpftool-data-")
	Expect(err).NotTo(HaveOccurred())

	defer os.RemoveAll(tempDir)

	dataInFname := tempDir + "/data_in"
	dataOutFname := tempDir + "/data_out"

	ctxInFname := tempDir + "/ctx_in"
	ctxOutFname := tempDir + "/ctx_out"

	if err := os.WriteFile(dataInFname, dataIn, 0644); err != nil {
		return res, errors.Errorf("failed to write input data in file: %s", err)
	}

	if ctxIn != nil {
		if err := os.WriteFile(ctxInFname, ctxIn, 0644); err != nil {
			return res, errors.Errorf("failed to write input ctx in file: %s", err)
		}
	}

	args := []string{"prog", "run", "pinned", progName, "data_in", dataInFname, "data_out", dataOutFname}
	if ctxIn != nil {
		args = append(args, "ctx_in", ctxInFname, "ctx_out", ctxOutFname)
	}
	if N > 1 {
		args = append(args, "repeat", fmt.Sprintf("%d", N))
	}

	out, err := bpftool(args...)
	if err != nil {
		return res, err
	}

	if err := json.Unmarshal(out, &res); err != nil {
		return res, errors.Errorf("failed to unmarshall json: %s", err)
	}

	res.dataOut, err = os.ReadFile(dataOutFname)
	if err != nil {
		return res, errors.Errorf("failed to read output data from file: %s", err)
	}

	if ctxIn != nil {
		ctxOut, err := os.ReadFile(ctxOutFname)
		if err != nil {
			return res, errors.Errorf("failed to read output ctx from file: %s", err)
		}
		skbMark = binary.LittleEndian.Uint32(ctxOut[2*4 : 3*4])
	}

	return res, nil
}

type bpfProgRunFn func(data []byte) (bpfRunResult, error)

// runBpfUnitTest runs a small unit in isolation. It requires a small .c file
// that wraps the unit and compiles into a calico_unittest section.
func runBpfUnitTest(t *testing.T, source string, testFn func(bpfProgRunFn), opts ...testOption) {
	RegisterTestingT(t)

	topts := testOpts{
		subtests: true,
		logLevel: log.DebugLevel,
	}

	for _, o := range opts {
		o(&topts)
	}

	loglevel := log.GetLevel()
	if topts.logLevel != loglevel {
		defer log.SetLevel(loglevel)
		log.SetLevel(topts.logLevel)
	}

	tempDir, err := os.MkdirTemp("", "calico-bpf-")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir)

	objFname := "../../bpf-gpl/ut/" + strings.TrimSuffix(source, path.Ext(source)) + ".o"

	obj, err := objLoad(objFname, bpfFsDir, "IPv4", topts, true, false)
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = obj.UnpinPrograms(bpfFsDir) }()
	defer obj.Close()

	ctxIn := make([]byte, 18*4)

	runTest := func() {
		testFn(func(dataIn []byte) (bpfRunResult, error) {
			res, err := bpftoolProgRun(bpfFsDir+"/classifier_calico_unittest", dataIn, ctxIn)
			log.Debugf("dataIn  = %+v", dataIn)
			if err == nil {
				log.Debugf("dataOut = %+v", res.dataOut)
			}
			return res, err
		})
	}

	if topts.subtests {
		t.Run(source, func(_ *testing.T) {
			runTest()
		})
	} else {
		runTest()
	}
}

type testOpts struct {
	description   string
	subtests      bool
	logLevel      log.Level
	xdp           bool
	psnaStart     uint32
	psnatEnd      uint32
	hostNetworked bool
	progLog       string
	ipv6          bool
}

type testOption func(opts *testOpts)

func withSubtests(v bool) testOption {
	return func(o *testOpts) {
		o.subtests = v
	}
}

var _ = withSubtests

func withLogLevel(l log.Level) testOption {
	return func(o *testOpts) {
		o.logLevel = l
	}
}

var _ = withLogLevel

func withXDP() testOption {
	return func(o *testOpts) {
		o.xdp = true
	}
}

func withPSNATPorts(start, end uint16) testOption {
	return func(o *testOpts) {
		o.psnaStart = uint32(start)
		o.psnatEnd = uint32(end)
	}
}

func withHostNetworked() testOption {
	return func(o *testOpts) {
		o.hostNetworked = true
	}
}

func withIPv6() testOption {
	return func(o *testOpts) {
		o.ipv6 = true
	}
}

func withDescription(desc string) testOption {
	return func(o *testOpts) {
		o.description = desc
	}
}

// layersMatchFields matches all Exported fields and ignore the ones explicitly
// listed. It always ignores BaseLayer as that is not set by the tests.
func layersMatchFields(l gopacket.Layer, ignore ...string) types.GomegaMatcher {
	toIgnore := make(map[string]bool)
	for _, x := range ignore {
		toIgnore[x] = true
	}

	toIgnore["BaseLayer"] = true

	f := Fields{}
	v := reflect.Indirect(reflect.ValueOf(l))
	if v.Kind() != reflect.Struct {
		return Reject()
	}

	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if !toIgnore[name] && v.Field(i).CanInterface() {
			val := v.Field(i).Interface()
			f[name] = Equal(val)
		}
	}

	return PointTo(MatchFields(IgnoreMissing|IgnoreExtras, f))
}

func udpResponseRaw(in []byte) []byte {
	pkt := gopacket.NewPacket(in, layers.LayerTypeEthernet, gopacket.Default)
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ethR := ethL.(*layers.Ethernet)
	ethR.SrcMAC, ethR.DstMAC = ethR.DstMAC, ethR.SrcMAC

	ipv4L := pkt.Layer(layers.LayerTypeIPv4)
	ipv4R := ipv4L.(*layers.IPv4)
	ipv4R.SrcIP, ipv4R.DstIP = ipv4R.DstIP, ipv4R.SrcIP

	udpL := pkt.Layer(layers.LayerTypeUDP)
	udpR := udpL.(*layers.UDP)
	udpR.SrcPort, udpR.DstPort = udpR.DstPort, udpR.SrcPort

	_ = udpR.SetNetworkLayerForChecksum(ipv4R)

	out := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv4R, udpR, gopacket.Payload(pkt.ApplicationLayer().Payload()))
	Expect(err).NotTo(HaveOccurred())

	return out.Bytes()
}

func tcpResponseRaw(in []byte) []byte {
	pkt := gopacket.NewPacket(in, layers.LayerTypeEthernet, gopacket.Default)
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ethR := ethL.(*layers.Ethernet)
	ethR.SrcMAC, ethR.DstMAC = ethR.DstMAC, ethR.SrcMAC

	ipv4L := pkt.Layer(layers.LayerTypeIPv4)
	ipv4R := ipv4L.(*layers.IPv4)
	ipv4R.SrcIP, ipv4R.DstIP = ipv4R.DstIP, ipv4R.SrcIP

	tcpL := pkt.Layer(layers.LayerTypeTCP)
	tcpR := tcpL.(*layers.TCP)
	tcpR.SrcPort, tcpR.DstPort = tcpR.DstPort, tcpR.SrcPort

	if tcpR.SYN {
		tcpR.ACK = true
	}

	_ = tcpR.SetNetworkLayerForChecksum(ipv4R)

	out := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv4R, tcpR, gopacket.Payload(pkt.ApplicationLayer().Payload()))
	Expect(err).NotTo(HaveOccurred())

	return out.Bytes()
}

func dumpNATMap(natMap bpf.Map) {
	nt, err := nat.LoadFrontendMap(natMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range nt {
		fmt.Printf("%s : %s\n", k, v)
	}
}

func resetMap(m bpf.Map) {
	err := m.Iter(func(_, _ []byte) bpf.IteratorAction {
		return bpf.IterDelete
	})
	Expect(err).NotTo(HaveOccurred())
}

func dumpCTMap(ctMap bpf.Map) {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("Conntrack dump:\n")
	for k, v := range ct {
		fmt.Printf("- %s : %s\n", k, v)
	}
	fmt.Printf("\n")
}

func resetCTMap(ctMap bpf.Map) {
	resetMap(ctMap)
}

func saveCTMap(ctMap bpf.Map) conntrack.MapMem {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	return ct
}

func restoreCTMap(ctMap bpf.Map, m conntrack.MapMem) {
	for k, v := range m {
		err := ctMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func dumpRTMap(rtMap bpf.Map) {
	rt, err := routes.LoadMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range rt {
		fmt.Printf("%15s: %s\n", k.Dest(), v)
	}
}

func resetRTMap(rtMap bpf.Map) {
	resetMap(rtMap)
}

func saveRTMap(rtMap bpf.Map) routes.MapMem {
	rt, err := routes.LoadMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	return rt
}

func restoreRTMap(rtMap bpf.Map, m routes.MapMem) {
	for k, v := range m {
		err := rtMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func dumpARPMap(arpMap bpf.Map) {
	ct, err := arp.LoadMapMem(arpMap)
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("ARP dump:\n")
	for k, v := range ct {
		fmt.Printf("- %s : %s\n", k, v)
	}
	fmt.Printf("\n")
}

func saveARPMap(ctMap bpf.Map) arp.MapMem {
	m, err := arp.LoadMapMem(arpMap)
	Expect(err).NotTo(HaveOccurred())
	return m
}

var ethDefault = &layers.Ethernet{
	SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
	DstMAC:       []byte{0, 0, 0, 0, 0, 2},
	EthernetType: layers.EthernetTypeIPv4,
}

var payloadDefault = []byte("ABCDEABCDEXXXXXXXXXXXX")

var srcIP = net.IPv4(1, 1, 1, 1)
var dstIP = net.IPv4(2, 2, 2, 2)
var srcV4CIDR = ip.CIDRFromNetIP(srcIP).(ip.V4CIDR)
var dstV4CIDR = ip.CIDRFromNetIP(dstIP).(ip.V4CIDR)

var ipv4Default = &layers.IPv4{
	Version:  4,
	IHL:      5,
	TTL:      64,
	Flags:    layers.IPv4DontFragment,
	SrcIP:    srcIP,
	DstIP:    dstIP,
	Protocol: layers.IPProtocolUDP,
}

var srcIPv6 = net.IP([]byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
var dstIPv6 = net.IP([]byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

var ipv6Default = &layers.IPv6{
	Version:    6,
	HopLimit:   64,
	SrcIP:      srcIPv6,
	DstIP:      dstIPv6,
	NextHeader: layers.IPProtocolUDP,
}

var udpDefault = &layers.UDP{
	SrcPort: 1234,
	DstPort: 5678,
}

func testPacket(eth *layers.Ethernet, l3 gopacket.Layer, l4 gopacket.Layer, payload []byte) (
	*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	pkt := Packet{
		eth:     eth,
		l3:      l3,
		l4:      l4,
		payload: payload,
	}
	err := pkt.Generate()
	return pkt.eth, pkt.ipv4, pkt.l4, pkt.payload, pkt.bytes, err
}

type Packet struct {
	eth        *layers.Ethernet
	l3         gopacket.Layer
	ipv4       *layers.IPv4
	ipv6       *layers.IPv6
	l4         gopacket.Layer
	udp        *layers.UDP
	tcp        *layers.TCP
	icmp       *layers.ICMPv4
	icmpv6     *layers.ICMPv6
	payload    []byte
	bytes      []byte
	layers     []gopacket.SerializableLayer
	length     int
	l4Protocol layers.IPProtocol
	l3Protocol layers.EthernetType
}

func (pkt *Packet) handlePayload() {
	if pkt.payload == nil {
		pkt.payload = payloadDefault
	}
	pkt.length = len(pkt.payload)
	pkt.layers = []gopacket.SerializableLayer{gopacket.Payload(pkt.payload)}
}

func (pkt *Packet) handleL4() error {
	if pkt.l4 == nil {
		pkt.l4 = udpDefault
	}

	switch v := pkt.l4.(type) {
	case *layers.UDP:
		pkt.udp = v
		pkt.length += 8
		pkt.udp.Length = uint16(pkt.length)
		pkt.l4Protocol = layers.IPProtocolUDP
		pkt.layers = append(pkt.layers, pkt.udp)
	case *layers.TCP:
		pkt.tcp = v
		pkt.length += 20
		pkt.l4Protocol = layers.IPProtocolTCP
		pkt.layers = append(pkt.layers, pkt.tcp)
	case *layers.ICMPv4:
		pkt.icmp = v
		pkt.length += 8
		pkt.l4Protocol = layers.IPProtocolICMPv4
		pkt.layers = append(pkt.layers, pkt.icmp)
	case *layers.ICMPv6:
		pkt.icmpv6 = v
		pkt.length += 8
		pkt.l4Protocol = layers.IPProtocolICMPv6
		pkt.layers = append(pkt.layers, pkt.icmpv6)
	default:
		return errors.Errorf("unrecognized l4 layer type %t", pkt.l4)
	}
	return nil
}

func (pkt *Packet) handleL3() error {
	if pkt.l3 == nil {
		pkt.l3 = ipv4Default
	}

	switch v := pkt.l3.(type) {
	case *layers.IPv4:
		pkt.ipv4 = v
		pkt.length += 5 * 4
		pkt.l3Protocol = layers.EthernetTypeIPv4
		pkt.ipv4.Protocol = pkt.l4Protocol
		pkt.ipv4.Length = uint16(pkt.length)
		pkt.layers = append(pkt.layers, pkt.ipv4)
	case *layers.IPv6:
		pkt.ipv6 = v
		pkt.l3Protocol = layers.EthernetTypeIPv6
		pkt.ipv6.NextHeader = pkt.l4Protocol
		pkt.ipv6.Length = uint16(pkt.length)
		pkt.layers = append(pkt.layers, pkt.ipv6)
	default:
		return errors.Errorf("unrecognized l3 layer type %t", pkt.l3)
	}
	return nil
}

func (pkt *Packet) handleEthernet() {
	if pkt.eth == nil {
		pkt.eth = ethDefault
	}
	pkt.eth.EthernetType = pkt.l3Protocol
	pkt.layers = append(pkt.layers, pkt.eth)
}

func (pkt *Packet) setChecksum() {
	switch pkt.l4Protocol {
	case layers.IPProtocolUDP:
		if pkt.l3Protocol == layers.EthernetTypeIPv6 {
			_ = pkt.udp.SetNetworkLayerForChecksum(pkt.ipv6)
		} else {
			_ = pkt.udp.SetNetworkLayerForChecksum(pkt.ipv4)
		}
	case layers.IPProtocolTCP:
		if pkt.l3Protocol == layers.EthernetTypeIPv6 {
			_ = pkt.tcp.SetNetworkLayerForChecksum(pkt.ipv6)
		} else {
			_ = pkt.tcp.SetNetworkLayerForChecksum(pkt.ipv4)
		}
	}
}

func (pkt *Packet) Generate() error {
	pkt.handlePayload()
	err := pkt.handleL4()
	if err != nil {
		return err
	}

	err = pkt.handleL3()
	if err != nil {
		return err
	}

	pkt.handleEthernet()
	pkt.setChecksum()
	pkt.bytes, err = generatePacket(pkt.layers)
	return err
}

func generatePacket(layers []gopacket.SerializableLayer) ([]byte, error) {
	pkt := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true})
	if err != nil {
		return nil, fmt.Errorf("Failed to init packet buffer: %w", err)
	}

	for i, layer := range layers {
		log.Infof("Layer %d: %v", i, layer)
		if layer == nil {
			continue
		}
		err = layer.SerializeTo(pkt, gopacket.SerializeOptions{ComputeChecksums: true})
		if err != nil {
			return nil, fmt.Errorf("Failed to serialize packet: %w", err)
		}
	}
	return pkt.Bytes(), nil
}

func testPacketUDPDefault() (*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	return testPacket(nil, nil, nil, nil)
}

func testPacketUDPDefaultNP(destIP net.IP) (*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	if destIP == nil {
		return testPacketUDPDefault()
	}

	ip := *ipv4Default
	ip.DstIP = destIP

	return testPacket(nil, &ip, nil, nil)
}

func resetBPFMaps() {
	resetCTMap(ctMap)
	resetRTMap(rtMap)
	resetMap(fsafeMap)
	resetMap(natMap)
	resetMap(natBEMap)
}

func TestMapIterWithDelete(t *testing.T) {
	RegisterTestingT(t)

	m := (&bpf.MapContext{}).NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/cali_tmap",
		Type:       "hash",
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 1000,
		Name:       "cali_tmap",
		Flags:      unix.BPF_F_NO_PREALLOC,
	})

	err := m.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 10; i++ {
		var k, v [8]byte

		binary.LittleEndian.PutUint64(k[:], uint64(i))
		binary.LittleEndian.PutUint64(v[:], uint64(i*7))

		err := m.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}

	out := make(map[uint64]uint64)

	cnt := 0
	err = m.Iter(func(K, V []byte) bpf.IteratorAction {
		k := binary.LittleEndian.Uint64(K)
		v := binary.LittleEndian.Uint64(V)

		out[k] = v
		cnt++

		return bpf.IterDelete
	})
	Expect(err).NotTo(HaveOccurred())

	Expect(cnt).To(Equal(10))

	for i := 0; i < 10; i++ {
		Expect(out).To(HaveKey(uint64(i)))
		Expect(out[uint64(i)]).To(Equal(uint64(i * 7)))
	}
}

func TestMapIterWithDeleteLastOfBatch(t *testing.T) {
	RegisterTestingT(t)

	m := (&bpf.MapContext{}).NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/cali_tmap",
		Type:       "hash",
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 1000,
		Name:       "cali_tmap",
		Flags:      unix.BPF_F_NO_PREALLOC,
	})

	err := m.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 40; i++ {
		var k, v [8]byte

		binary.LittleEndian.PutUint64(k[:], uint64(i))
		binary.LittleEndian.PutUint64(v[:], uint64(i*7))

		err := m.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}

	out := make(map[uint64]uint64)

	cnt := 0
	err = m.Iter(func(K, V []byte) bpf.IteratorAction {
		k := binary.LittleEndian.Uint64(K)
		v := binary.LittleEndian.Uint64(V)

		out[k] = v

		cnt++
		// Delete the last of the first batch. Must not make the iteration to
		// restart from the beginning.
		if cnt == bpf.MapIteratorNumKeys {
			return bpf.IterDelete
		}
		return bpf.IterNone
	})
	Expect(err).NotTo(HaveOccurred())

	Expect(cnt).To(Equal(40))

	for i := 0; i < 40; i++ {
		Expect(out).To(HaveKey(uint64(i)))
		Expect(out[uint64(i)]).To(Equal(uint64(i * 7)))
	}
}

func TestJumpMap(t *testing.T) {
	RegisterTestingT(t)

	jumpMapFD := jumpMap.MapFD()
	pg := polprog.NewBuilder(idalloc.New(), ipsMap.MapFD(), stateMap.MapFD(), jumpMapFD, false)
	rules := polprog.Rules{}
	insns, err := pg.Instructions(rules)
	Expect(err).NotTo(HaveOccurred())
	progFD, err := bpf.LoadBPFProgramFromInsns(insns, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	Expect(err).NotTo(HaveOccurred())

	k := make([]byte, 4)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(progFD))

	err = bpf.UpdateMapEntry(jumpMapFD, k, v)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.DeleteMapEntry(jumpMapFD, k, 4)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.UpdateMapEntry(jumpMapFD, k, v)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.DeleteMapEntryIfExists(jumpMapFD, k, 4)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.DeleteMapEntryIfExists(jumpMapFD, k, 4)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.DeleteMapEntry(jumpMapFD, k, 4)
	Expect(err).To(HaveOccurred())
}
