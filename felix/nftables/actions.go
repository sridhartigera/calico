// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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

package nftables

import (
	"fmt"
	"math"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
)

type namespaceable interface {
	Namespace(string) generictables.Action
}

func Actions() generictables.ActionFactory {
	return &actionSet{}
}

type actionSet struct{}

func (s *actionSet) Allow() generictables.Action {
	return AcceptAction{}
}

func (s *actionSet) GoTo(target string) generictables.Action {
	return &GotoAction{Target: target}
}

func (s *actionSet) Return() generictables.Action {
	return ReturnAction{}
}

func (s *actionSet) Reject(with generictables.RejectWith) generictables.Action {
	// Convert the RejectWith to a string valid in nftables.
	switch with {
	case generictables.RejectWithTCPReset:
		return RejectAction{With: "tcp reset"}
	}
	if with != "" {
		logrus.WithField("reject-with", with).Panic("Unknown reject-with value")
	}
	return RejectAction{}
}

func (s *actionSet) SetMaskedMark(mark, mask uint32) generictables.Action {
	return SetMaskedMarkAction{
		Mark: mark,
		Mask: mask,
	}
}

func (s *actionSet) SetMark(mark uint32) generictables.Action {
	return SetMarkAction{
		Mark: mark,
	}
}

func (s *actionSet) ClearMark(mark uint32) generictables.Action {
	return ClearMarkAction{Mark: mark}
}

func (s *actionSet) Jump(target string) generictables.Action {
	return &JumpAction{Target: target}
}

func (s *actionSet) NoTrack() generictables.Action {
	return NoTrackAction{}
}

func (s *actionSet) Log(prefix string) generictables.Action {
	return LogAction{Prefix: prefix}
}

func (s *actionSet) SNAT(ip string) generictables.Action {
	return SNATAction{ToAddr: ip}
}

func (s *actionSet) DNAT(ip string, port uint16) generictables.Action {
	return DNATAction{DestAddr: ip, DestPort: port}
}

func (s *actionSet) Masq(toPorts string) generictables.Action {
	return MasqAction{ToPorts: toPorts}
}

func (s *actionSet) Drop() generictables.Action {
	return DropAction{}
}

func (s *actionSet) SetConnmark(mark, mask uint32) generictables.Action {
	return SetConnMarkAction{
		Mark: mark,
		Mask: mask,
	}
}

func (a *actionSet) Nflog(group uint16, prefix string, size int) generictables.Action {
	return NflogAction{
		Group:  group,
		Prefix: escapeLogPrefix(prefix),
		Size:   size,
	}
}

func (a *actionSet) LimitPacketRate(rate, burst int64, mark uint32) generictables.Action {
	return LimitPacketRateAction{
		Rate:  rate,
		Burst: burst,
		// Mark is not used on nftables mode
	}
}

func (a *actionSet) LimitNumConnections(num int64, rejectWith generictables.RejectWith) generictables.Action {
	return LimitNumConnectionsAction{
		Num:        num,
		RejectWith: rejectWith,
	}
}

func escapeLogPrefix(prefix string) string {
	return fmt.Sprintf("\"%s\"", prefix)
}

type Referrer interface {
	ReferencedChain() string
}

type GotoAction struct {
	Target   string
	TypeGoto struct{}
}

func (g GotoAction) ToFragment(features *environment.Features) string {
	return "goto " + g.Target
}

func (g GotoAction) String() string {
	return "Goto->" + g.Target
}

func (g GotoAction) ReferencedChain() string {
	return g.Target
}

func (g GotoAction) Namespace(ns string) generictables.Action {
	if strings.HasPrefix(g.Target, ns) {
		return g
	}

	n := g
	n.Target = ns + "-" + g.Target
	return n
}

var (
	_ Referrer      = GotoAction{}
	_ namespaceable = GotoAction{}
)

type JumpAction struct {
	Target   string
	TypeJump struct{}
}

func (g JumpAction) ToFragment(features *environment.Features) string {
	return "jump " + g.Target
}

func (g JumpAction) String() string {
	return "Jump->" + g.Target
}

func (g JumpAction) ReferencedChain() string {
	return g.Target
}

func (g JumpAction) Namespace(ns string) generictables.Action {
	if strings.HasPrefix(g.Target, ns) {
		return g
	}

	n := g
	n.Target = ns + "-" + g.Target
	return n
}

var (
	_ Referrer      = JumpAction{}
	_ namespaceable = JumpAction{}

	_ generictables.ReturnActionMarker = ReturnAction{}
)

type ReturnAction struct {
	TypeReturn struct{}
}

func (r ReturnAction) IsReturnAction() {
}

func (r ReturnAction) ToFragment(features *environment.Features) string {
	return "return"
}

func (r ReturnAction) String() string {
	return "Return"
}

type DropAction struct {
	TypeDrop struct{}
}

func (g DropAction) ToFragment(features *environment.Features) string {
	return "drop"
}

func (g DropAction) String() string {
	return "Drop"
}

type RejectAction struct {
	TypeReject struct{}
	With       string
}

func (g RejectAction) ToFragment(features *environment.Features) string {
	if g.With != "" {
		return fmt.Sprintf("reject with %s", g.With)
	}
	return "reject"
}

func (g RejectAction) String() string {
	return "Reject"
}

type LogAction struct {
	Prefix  string
	TypeLog struct{}
}

func (g LogAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf(`log prefix %s level info`, g.Prefix)
}

func (g LogAction) String() string {
	return "Log"
}

type AcceptAction struct {
	TypeAccept struct{}
}

func (g AcceptAction) ToFragment(features *environment.Features) string {
	return "accept"
}

func (g AcceptAction) String() string {
	return "Accept"
}

type DNATAction struct {
	DestAddr string
	DestPort uint16
	TypeDNAT struct{}
}

func (g DNATAction) ToFragment(features *environment.Features) string {
	if g.DestPort == 0 {
		return fmt.Sprintf("dnat to %s", g.DestAddr)
	} else {
		return fmt.Sprintf("dnat to %s:%d", g.DestAddr, g.DestPort)
	}
}

func (g DNATAction) String() string {
	return fmt.Sprintf("DNAT->%s:%d", g.DestAddr, g.DestPort)
}

type SNATAction struct {
	ToAddr   string
	TypeSNAT struct{}
}

func (g SNATAction) ToFragment(features *environment.Features) string {
	fullyRand := ""
	if features.SNATFullyRandom {
		fullyRand = " fully-random"
	}
	return fmt.Sprintf("snat to %s%s", g.ToAddr, fullyRand)
}

func (g SNATAction) String() string {
	return fmt.Sprintf("SNAT->%s", g.ToAddr)
}

type MasqAction struct {
	ToPorts  string
	TypeMasq struct{}
}

func (g MasqAction) ToFragment(features *environment.Features) string {
	fullyRand := ""
	if features.MASQFullyRandom {
		fullyRand = " fully-random"
	}
	if g.ToPorts != "" {
		// e.g., masquerade to :1024-65535
		return fmt.Sprintf("masquerade to %s"+fullyRand, g.ToPorts)
	}
	return "masquerade" + fullyRand
}

func (g MasqAction) String() string {
	return "Masq"
}

type ClearMarkAction struct {
	Mark          uint32
	TypeClearMark struct{}
}

func (c ClearMarkAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf("meta mark set mark & %#x", (c.Mark ^ 0xffffffff))
}

func (c ClearMarkAction) String() string {
	return fmt.Sprintf("Clear:%#x", c.Mark)
}

type SetMarkAction struct {
	Mark        uint32
	TypeSetMark struct{}
}

func (c SetMarkAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf("meta mark set mark or %#x", c.Mark)
}

func (c SetMarkAction) String() string {
	return fmt.Sprintf("Set:%#x", c.Mark)
}

type SetMaskedMarkAction struct {
	Mark              uint32
	Mask              uint32
	TypeSetMaskedMark struct{}
}

func (c SetMaskedMarkAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf("meta mark set mark & %#x ^ %#x", (c.Mask ^ 0xffffffff), c.Mark)
}

func (c SetMaskedMarkAction) String() string {
	return fmt.Sprintf("Set:%#x", c.Mark)
}

type NoTrackAction struct {
	TypeNoTrack struct{}
}

func (g NoTrackAction) ToFragment(features *environment.Features) string {
	return "notrack"
}

func (g NoTrackAction) String() string {
	return "NOTRACK"
}

type SaveConnMarkAction struct {
	SaveMask     uint32
	TypeConnMark struct{}
}

func (c SaveConnMarkAction) ToFragment(features *environment.Features) string {
	if c.SaveMask == 0 {
		return "ct mark set mark"
	}
	return fmt.Sprintf("ct mark set mark & %#x", c.SaveMask)
}

func (c SaveConnMarkAction) String() string {
	return fmt.Sprintf("SaveConnMarkWithMask:%#x", c.SaveMask)
}

type RestoreConnMarkAction struct {
	RestoreMask  uint32
	TypeConnMark struct{}
}

func (c RestoreConnMarkAction) ToFragment(features *environment.Features) string {
	if c.RestoreMask == 0 {
		// If Mask field is ignored, restore full mark.
		return "meta mark set ct mark"
	}
	return fmt.Sprintf("meta mark set ct mark & %#x", c.RestoreMask)
}

func (c RestoreConnMarkAction) String() string {
	return fmt.Sprintf("RestoreConnMarkWithMask:%#x", c.RestoreMask)
}

type SetConnMarkAction struct {
	Mark         uint32
	Mask         uint32
	TypeConnMark struct{}
}

func (c SetConnMarkAction) ToFragment(features *environment.Features) string {
	if c.Mask == 0 {
		// If Mask field is ignored, default to full mark.
		return fmt.Sprintf("ct mark set %#x", c.Mark)
	}
	return fmt.Sprintf("ct mark set ct mark & %#x ^ %#x", (c.Mask ^ 0xffffffff), c.Mark)
}

func (c SetConnMarkAction) String() string {
	return fmt.Sprintf("SetConnMarkWithMask:%#x/%#x", c.Mark, c.Mask)
}

type NflogAction struct {
	Group  uint16
	Prefix string
	Size   int
}

func (n NflogAction) ToFragment(features *environment.Features) string {
	size := 80
	if n.Size != 0 {
		size = n.Size
	}
	if n.Size < 0 {
		return fmt.Sprintf("log prefix %s group %d", n.Prefix, n.Group)
	} else {
		return fmt.Sprintf("log prefix %s snaplen %d group %d", n.Prefix, size, n.Group)
	}
}

func (n NflogAction) String() string {
	return fmt.Sprintf("Nflog:g=%d,p=%s", n.Group, n.Prefix)
}

type LimitPacketRateAction struct {
	Rate  int64
	Burst int64
	// Mark is not used on nftables mode
	TypeLimitPacketRate struct{}
}

func (a LimitPacketRateAction) ToFragment(features *environment.Features) string {
	// Rate and Burst are limited to XT_LIMIT_SCALE (10k)
	// See https://github.com/torvalds/linux/blob/16b70698aa3ae7888826d0c84567c72241cf6713/include/uapi/linux/netfilter/xt_limit.h#L8
	if a.Rate < 0 || a.Rate > 10000 {
		logrus.WithField("rate", a.Rate).Panic("Invalid rate")
	}
	if a.Burst < 1 || a.Burst > 10000 {
		logrus.WithField("burst", a.Burst).Panic("Invalid burst")
	}
	return fmt.Sprintf("limit rate over %d/second burst %d packets drop", a.Rate, a.Burst)
}

func (a LimitPacketRateAction) String() string {
	return fmt.Sprintf("LimitPacketRate:%d/s,burst:%d", a.Rate, a.Burst)
}

type LimitNumConnectionsAction struct {
	Num                     int64
	RejectWith              generictables.RejectWith
	TypeLimitNumConnections struct{}
}

func (a LimitNumConnectionsAction) ToFragment(features *environment.Features) string {
	rejectWith := ""
	switch a.RejectWith {
	case generictables.RejectWithTCPReset:
		rejectWith = "tcp reset"
	default:
		logrus.WithField("reject-with", a.RejectWith).Panic("Unknown reject-with value")
	}
	// The connection limit is an uint32 (maximum value 4294967295).
	// See https://github.com/torvalds/linux/blob/16b70698aa3ae7888826d0c84567c72241cf6713/include/uapi/linux/netfilter/xt_connlimit.h#L25
	if a.Num < 0 || a.Num > math.MaxUint32 {
		logrus.WithField("rate", a.Num).Panic("Invalid limit")
	}
	return fmt.Sprintf("ct count over %d reject with %s", a.Num, rejectWith)
}

func (a LimitNumConnectionsAction) String() string {
	return fmt.Sprintf("LimitNumConnectionsAction:%d,rejectWith:%s", a.Num, a.RejectWith)
}
