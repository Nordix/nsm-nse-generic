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
	"net/url"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vlan"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

const (
	netNSFilename = "/proc/thread-self/ns/net"
)

// TODO: add support for multiple services
type vlanMapServer struct {
	baseInterface string
	vlanTag       int32
}

// NewServer - creates a NetworkServiceServer that requests a vlan interface and populates the netns inode
func NewServer(baseInterface string, vlanID int32) networkservice.NetworkServiceServer {
	v := &vlanMapServer{
		baseInterface: baseInterface,
		vlanTag:       vlanID,
	}
	return v
}

func (v *vlanMapServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {

	if conn := request.GetConnection(); conn != nil {
		if mechanism := vlan.ToMechanism(conn.GetMechanism()); mechanism != nil {
			mechanism.SetNetNSURL((&url.URL{Scheme: "file", Path: netNSFilename}).String())
			mechanism.SetVlanID(uint32(v.vlanTag))
			mechanism.SetBaseInterfaceName(v.baseInterface)
		}
	}
	if request.GetConnection() == nil {
		request.Connection = &networkservice.Connection{}
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
