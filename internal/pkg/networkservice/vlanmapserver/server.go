// Copyright (c) 2021 Nordix Foundation.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package vlanmapserver provides chain element implementing `network service -> { BASEIF, VLAN }` mapping
package vlanmapserver

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vlan"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"

	"github.com/Nordix/nsm-nse-generic/internal/pkg/config"
)

const (
	netNSFilename      = "/proc/thread-self/ns/net"
	serviceDomainLabel = "serviceDomain"
)

// TODO: add support for multiple services
type vlanMapServer struct {
	entries map[string]*entry
}
type entry struct {
	vlanTag int32
	domain  string
}

// NewServer - creates a NetworkServiceServer that requests a vlan interface and populates the netns inode
func NewServer(cfg *config.Config) networkservice.NetworkServiceServer {
	v := &vlanMapServer{
		entries: make(map[string]*entry, len(cfg.Services)),
	}

	for i := range cfg.Services {
		service := &cfg.Services[i]
		v.entries[service.Name] = &entry{
			vlanTag: service.VLANTag,
			domain:  service.Domain,
		}
	}
	return v
}

func (v *vlanMapServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	conn := request.GetConnection()
	entry, ok := v.entries[conn.GetNetworkService()]

	if !ok {
		return nil, errors.Errorf("network service is not supported: %s", conn.GetNetworkService())
	}

	if mechanism := vlan.ToMechanism(conn.GetMechanism()); mechanism != nil {
		mechanism.SetVlanID(uint32(entry.vlanTag))

		conn.Labels = make(map[string]string, 1)
		conn.Labels[serviceDomainLabel] = entry.domain
	}
	if request.GetConnection().GetContext() == nil {
		request.GetConnection().Context = &networkservice.ConnectionContext{}
	}
	request.GetConnection().GetContext().MTU = 0
	return next.Server(ctx).Request(ctx, request)
}

func (v *vlanMapServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	return next.Server(ctx).Close(ctx, conn)
}
