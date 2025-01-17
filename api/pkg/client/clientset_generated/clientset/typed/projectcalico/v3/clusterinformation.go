// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package v3

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	scheme "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// ClusterInformationsGetter has a method to return a ClusterInformationInterface.
// A group's client should implement this interface.
type ClusterInformationsGetter interface {
	ClusterInformations() ClusterInformationInterface
}

// ClusterInformationInterface has methods to work with ClusterInformation resources.
type ClusterInformationInterface interface {
	Create(ctx context.Context, clusterInformation *v3.ClusterInformation, opts v1.CreateOptions) (*v3.ClusterInformation, error)
	Update(ctx context.Context, clusterInformation *v3.ClusterInformation, opts v1.UpdateOptions) (*v3.ClusterInformation, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v3.ClusterInformation, error)
	List(ctx context.Context, opts v1.ListOptions) (*v3.ClusterInformationList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v3.ClusterInformation, err error)
	ClusterInformationExpansion
}

// clusterInformations implements ClusterInformationInterface
type clusterInformations struct {
	*gentype.ClientWithList[*v3.ClusterInformation, *v3.ClusterInformationList]
}

// newClusterInformations returns a ClusterInformations
func newClusterInformations(c *ProjectcalicoV3Client) *clusterInformations {
	return &clusterInformations{
		gentype.NewClientWithList[*v3.ClusterInformation, *v3.ClusterInformationList](
			"clusterinformations",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *v3.ClusterInformation { return &v3.ClusterInformation{} },
			func() *v3.ClusterInformationList { return &v3.ClusterInformationList{} }),
	}
}
