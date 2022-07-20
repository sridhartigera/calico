// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

//go:build fvtests

package fv_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"fmt"
	"time"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	. "github.com/projectcalico/calico/felix/fv/connectivity"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf test policy counters", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
		// Non-BPF run.
		return
	}

	var (
		infra        infrastructure.DatastoreInfra
		felixes      []*infrastructure.Felix
		calicoClient client.Interface
		w            [2]*workload.Workload
		cc                 *Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.ExtraEnvVars["FELIX_BPFPolicyDebugEnabled"] = "true"
		felixes, calicoClient = infrastructure.StartNNodeTopology(1, opts, infra)
		for i := 0; i < 2; i++ {
			wIP := fmt.Sprintf("10.65.0.%d", i+2)
			w[i] = workload.Run(felixes[0], fmt.Sprintf("w%d", i), "default", wIP, "8055", "tcp")
			w[i].WorkloadEndpoint.Labels = map[string]string{"name": w[i].Name}
			w[i].ConfigureInInfra(infra)
		}
		cc = &Checker{CheckSNAT: true,}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		for i := 0; i < 2; i++ {
			w[i].Stop()
		}
		felixes[0].Stop()
		infra.Stop()
	})

	createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
		log.WithField("policy", dumpResource(policy)).Info("Creating policy")
		policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		return policy
	}

	It("should update rule counters", func() {

		pol := api.NewGlobalNetworkPolicy()
		pol.Namespace = "fv"
		pol.Name = "policy-test"
		//pol.Spec.Selector = w[0].NameSelector()
		pol.Spec.Selector = "all()"
		pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
		pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
		pol = createPolicy(pol)
		cc.ExpectSome(w[1], w[0])
		cc.CheckConnectivity()
		time.Sleep(200 * time.Second)
	})
})
