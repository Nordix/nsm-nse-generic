// Copyright (c) 2020-2021 Doc.ai and/or its affiliates.
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

// +build !windows

package main

import (
	"context"
	"io/ioutil"
	"net/url"
	"os"
	"fmt"
	"path/filepath"
	"time"

	"github.com/edwarnicke/grpcfd"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"github.com/golang/protobuf/ptypes/empty"

	"github.com/Nordix/simple-ipam/pkg/ipam"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"
	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	registryrefresh "github.com/networkservicemesh/sdk/pkg/registry/common/refresh"
	registrysendfd "github.com/networkservicemesh/sdk/pkg/registry/common/sendfd"
	registrychain "github.com/networkservicemesh/sdk/pkg/registry/core/chain"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

// Config holds configuration parameters from environment variables
type Config struct {
	Name             string            `default:"nse-generic" desc:"Name of the endpoint"`
	ConnectTo        url.URL           `default:"unix:///var/lib/networkservicemesh/nsm.io.sock" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime time.Duration     `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`
	ServiceName      string            `default:"nse-generic" desc:"Name of providing service" split_words:"true"`
	Labels           map[string]string `default:"" desc:"Endpoint labels"`
	CidrPrefix       string          `default:"169.254.0.0/16" desc:"CIDR Prefix to assign IPs from" split_words:"true"`
	Ipv6Prefix       string          `default:"" desc:"Ipv6 Prefix for dual-stack" split_words:"true"`
	Point2Point      bool            `default:"True" desc:"Use /32 or /128 addresses" split_words:"true"`
}

// Process prints and processes env to config
func (c *Config) Process() error {
	if err := envconfig.Usage("nse", c); err != nil {
		return errors.Wrap(err, "cannot show usage of envconfig nse")
	}
	if err := envconfig.Process("nse", c); err != nil {
		return errors.Wrap(err, "cannot process envconfig nse")
	}
	return nil
}

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	config := new(Config)
	if err := config.Process(); err != nil {
		logrus.Fatal(err.Error())
	}

	logrus.Infof("Config: %#v", config)

	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		logrus.Fatalf("error getting x509 source: %+v", err)
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		logrus.Fatalf("error getting x509 svid: %+v", err)
	}
	logrus.Infof("SVID: %q", svid.ID)

	ipam, err := ipam.New(config.CidrPrefix)
	if err != nil {
		logrus.Fatalf("Could not create ipam for %s; %+v", config.CidrPrefix, err)
	}


	responderEndpoint := endpoint.NewServer(
		ctx,
		config.Name,
		authorize.NewServer(),
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		&simpleIpam{
			ipam: ipam,
			ipv6Prefix: config.Ipv6Prefix,
			point2Point: config.Point2Point,
		},
		recvfd.NewServer(),
		mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
			kernelmech.MECHANISM: kernel.NewServer(),
		}),
		sendfd.NewServer())

	
	creds := grpc.Creds(
		grpcfd.TransportCredentials(
			credentials.NewTLS(
				tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny()),
			),
		),
	)
	server := grpc.NewServer(creds)
	responderEndpoint.Register(server)
	tmpDir, err := ioutil.TempDir("", config.Name)
	if err != nil {
		logrus.Fatalf("error creating tmpDir %+v", err)
	}
	defer func(tmpDir string) { _ = os.Remove(tmpDir) }(tmpDir)
	listenOn := &(url.URL{Scheme: "unix", Path: filepath.Join(tmpDir, "listen.on")})
	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)
	logrus.Infof("grpc server started")

	cc, err := grpc.DialContext(ctx,
		grpcutils.URLToTarget(&config.ConnectTo),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithTransportCredentials(
			grpcfd.TransportCredentials(
				credentials.NewTLS(
					tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny()),
				),
			),
		),
	)
	if err != nil {
		logrus.Fatalf("error establishing grpc connection to registry server %+v", err)
	}

	_, err = registryapi.NewNetworkServiceRegistryClient(cc).Register(context.Background(), &registryapi.NetworkService{
		Name:    config.ServiceName,
		Payload: payload.IP,
	})

	if err != nil {
		logrus.Fatalf("unable to register ns %+v", err)
	}

	registryClient := registrychain.NewNetworkServiceEndpointRegistryClient(
		registryrefresh.NewNetworkServiceEndpointRegistryClient(),
		registrysendfd.NewNetworkServiceEndpointRegistryClient(),
		registryapi.NewNetworkServiceEndpointRegistryClient(cc),
	)
	nse, err := registryClient.Register(context.Background(), &registryapi.NetworkServiceEndpoint{
		Name:                config.Name,
		NetworkServiceNames: []string{config.ServiceName},
		NetworkServiceLabels: map[string]*registryapi.NetworkServiceLabels{
			config.ServiceName: {
				Labels: config.Labels,
			},
		},
		Url: listenOn.String(),
	})
	logrus.Infof("nse: %+v", nse)

	if err != nil {
		logrus.Fatalf("unable to register nse %+v", err)
	}

	// wait for server to exit
	<-ctx.Done()
}

func exitOnErr(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		logrus.Fatal(err)
	default:
	}
	// Otherwise wait for an error in the background to log and cancel
	go func(ctx context.Context, errCh <-chan error) {
		err := <-errCh
		logrus.Error(err)
		cancel()
	}(ctx, errCh)
}

type simpleIpam struct {
	ipam *ipam.IPAM
	ipv6Prefix string
	point2Point bool
	myIP string
}

func (s *simpleIpam) Request(
	ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {

	conn := request.GetConnection()
	if conn.GetContext() == nil {
		conn.Context = &networkservice.ConnectionContext{}
	}
	context := conn.GetContext()
	if context.GetIpContext() == nil {
		context.IpContext = &networkservice.IPContext{}
	}
	ipContext := context.GetIpContext()

	if s.point2Point {
		// Compute the mask "/32" or "/128"
		_, bits := s.ipam.CIDR.Mask.Size()
		mask := fmt.Sprintf("/%d", bits)

		if addr, err := s.ipam.Allocate(); err != nil {
			return nil, err
		} else {
			ipContext.SrcIpAddr = addr.String() + mask
			ipContext.DstRoutes = []*networkservice.Route{
				{
					Prefix: addr.String() + mask,
				},
			}
		}

		if addr, err := s.ipam.Allocate(); err != nil {
			return nil, err
		} else {
			ipContext.DstIpAddr = addr.String() + mask
			ipContext.SrcRoutes = []*networkservice.Route{
				{
					Prefix: addr.String() + mask,
				},
			}
		}
		return next.Server(ctx).Request(ctx, request)
	}

	// Not point-to-point connection

	// Compute the mask. Same as the ipam.CIDR
	ones, _ := s.ipam.CIDR.Mask.Size()
	mask := fmt.Sprintf("/%d", ones)

	// The NSE has only one interface hence only one address
	if s.myIP == "" {
		if addr, err := s.ipam.Allocate(); err != nil {
			return nil, err
		} else {
			s.myIP = addr.String() + mask
		}
	}
	ipContext.SrcIpAddr = s.myIP
	if addr, err := s.ipam.Allocate(); err != nil {
		return nil, err
	} else {
		ipContext.DstIpAddr = addr.String() + mask
	}

	return next.Server(ctx).Request(ctx, request)
}
func (s *simpleIpam) Close(
	ctx context.Context, conn *networkservice.Connection) (_ *empty.Empty, err error) {
	return next.Server(ctx).Close(ctx, conn)
}
