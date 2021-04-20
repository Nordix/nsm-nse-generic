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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/edwarnicke/grpcfd"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/Nordix/simple-ipam/pkg/ipam"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	vlanmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vlan"
	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"
	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk-kernel/pkg/kernel/networkservice/common/mechanisms/vlan"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	registryrefresh "github.com/networkservicemesh/sdk/pkg/registry/common/refresh"
	registrysendfd "github.com/networkservicemesh/sdk/pkg/registry/common/sendfd"
	registrychain "github.com/networkservicemesh/sdk/pkg/registry/core/chain"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	meridioipam "github.com/nordix/meridio/pkg/ipam"
	"github.com/vishvananda/netlink"
)

// Config holds configuration parameters from environment variables
type Config struct {
	Name             string            `default:"nse-generic" desc:"Name of the endpoint"`
	ConnectTo        url.URL           `default:"unix:///var/lib/networkservicemesh/nsm.io.sock" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime time.Duration     `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`
	ServiceName      string            `default:"nse-generic" desc:"Name of providing service" split_words:"true"`
	Labels           map[string]string `default:"" desc:"Endpoint labels"`
	CidrPrefix       string            `default:"169.254.0.0/16" desc:"CIDR Prefix to assign IPs from" split_words:"true"`
	Ipv6Prefix       string            `default:"" desc:"Ipv6 Prefix for dual-stack" split_words:"true"`
	Point2Point      bool              `default:"True" desc:"Use /32 or /128 addresses" split_words:"false"`
	MeridioIpam      string            `default:"" desc:"Example: meridio-ipam:7777" split_words:"true"`
}

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	config := processConfig()
	source := getX509Source(ctx)

	responderEndpoint := endpoint.NewServer(
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		endpoint.WithName(config.Name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			newSimpleIpam(config),
			recvfd.NewServer(),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				kernelmech.MECHANISM: kernel.NewServer(),
				vlanmech.MECHANISM:   vlan.NewServer(),
			}),
			&mechanismClient{},
			sendfd.NewServer()))

	serverCreds := grpc.Creds(
		grpcfd.TransportCredentials(
			credentials.NewTLS(
				tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny()),
			),
		),
	)
	clientCreds := grpc.WithTransportCredentials(
		grpcfd.TransportCredentials(
			credentials.NewTLS(
				tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny()),
			),
		),
	)

	server := grpc.NewServer(serverCreds)
	responderEndpoint.Register(server)
	listenOn := &(url.URL{Scheme: "unix", Path: "/tmp/listen.on"})
	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)
	logrus.Infof("grpc server started")

	cc, err := grpc.DialContext(ctx,
		grpcutils.URLToTarget(&config.ConnectTo),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		clientCreds,
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

func getX509Source(ctx context.Context) *workloadapi.X509Source {
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		logrus.Fatalf("error getting x509 source: %+v", err)
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		logrus.Fatalf("error getting x509 svid: %+v", err)
	}
	logrus.Infof("SVID: %q", svid.ID)
	return source
}

// Process prints and processes env to config
func processConfig() *Config {
	c := new(Config)
	if err := envconfig.Process("nse", c); err != nil {
		logrus.Fatalf("cannot process envconfig nse %+v", err)
	}
	logrus.Infof("Config: %#v", c)
	return c
}

type simpleIpam struct {
	ipam        *ipam.IPAM
	ipv6Prefix  string
	point2Point bool
	myIP        string
	bits        int
	ones        int
}

func newSimpleIpam(config *Config) *simpleIpam {
	_, net, err := net.ParseCIDR(config.CidrPrefix)
	if err != nil {
		logrus.Fatalf("Could not parse cidr %s; %+v", config.CidrPrefix, err)
	}
	sipam := &simpleIpam{
		ipv6Prefix:  config.Ipv6Prefix,
		point2Point: config.Point2Point,
	}
	sipam.ones, sipam.bits = net.Mask.Size()
	
	if config.MeridioIpam != "" {
		// Request a CIDR from the meridio ipam service.
		// We require a mask <= 16 for the configured CIDR and request a /24 IPv4 cidr.
		if sipam.bits != 32 || sipam.ones > 16 {
			logrus.Fatalf("MeridioIpam requies IPv4 with mask <= 16: %s", config.CidrPrefix)
		}
        ipamClient, err := meridioipam.NewIpamClient(config.MeridioIpam)
        if err != nil {
			logrus.Fatalf("Error creating New Ipam Client: %+v", err)
        }
		subnetPool, err := netlink.ParseAddr(config.CidrPrefix)
        proxySubnet, err := ipamClient.AllocateSubnet(subnetPool, 24)
        if err != nil {
			logrus.Fatalf("Error AllocateSubnet: %+v", err)
        }
		logrus.Infof("Using MeridioIpam cidr; %s", proxySubnet.String())
		sipam.ipam, err = ipam.New(proxySubnet.String())
		if err != nil {
			logrus.Fatalf("Could not create ipam for %s; %+v", config.CidrPrefix, err)
		}
	} else {
		sipam.ipam, err = ipam.New(config.CidrPrefix)
		if err != nil {
			logrus.Fatalf("Could not create ipam for %s; %+v", config.CidrPrefix, err)
		}
	}
	return sipam
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
		mask := fmt.Sprintf("/%d", s.bits)

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
	mask := fmt.Sprintf("/%d", s.ones)

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
	// TODO free addresses here?
	return next.Server(ctx).Close(ctx, conn)
}




// ----------------------------------------------------------------------

type mechanismClient struct {
	mutex sync.Mutex
}

func (k *mechanismClient) Request(
	ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {

	conn, err := next.Server(ctx).Request(ctx, request)
	if err != nil {
		return conn, err;
	}

	k.mutex.Lock()
	mechanisms, err := mechanismCallout(ctx)
	k.mutex.Unlock()
	if err != nil {
		logrus.Infof("mechanismCallout err %v", err)
	}

	// We only handle the "name" parameter from one (any) mechanism
	if len(mechanisms) > 0 {
		if mechanisms[0].Parameters != nil {
			if name, ok := mechanisms[0].Parameters["name"]; ok {
				conn.Mechanism.Parameters["name"] = name
			}
		}
	}

	// This call is just for logging the request
	err = requestCallout(ctx, &networkservice.NetworkServiceRequest{Connection:conn})
	if err != nil {
		logrus.Infof("requestCallout err %v", err)
	}
	return conn, err
}

func (k *mechanismClient) Close(
	ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	k.mutex.Lock()
	closeCallout(ctx, conn)
	k.mutex.Unlock()
	return next.Server(ctx).Close(ctx, conn)
}



// ----------------------------------------------------------------------
// Callout functions

func calloutProgram() string {
	callout := os.Getenv("CALLOUT")
	if callout == "" {
		return "/bin/nse.sh"
	}
	return callout
}

func initCallout() error {
	logrus.Infof("initCallout")
	cmd := exec.Command(calloutProgram(), "init")
	if out, err := cmd.CombinedOutput(); err != nil {
		return err
	} else {
		fmt.Println(string(out))
	}
	return nil
}

// Send the Request in json format on stdin to the callout script
func requestCallout(ctx context.Context, req *networkservice.NetworkServiceRequest) error {
	logrus.Infof("requestCallout")
	cmd := exec.Command(calloutProgram(), "request")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdin)
	go func() {
		defer stdin.Close()
		_ = enc.Encode(req)
	}()
	if out, err := cmd.Output(); err != nil {
		return err
	} else {
		fmt.Println(string(out))
	}
	return nil
}

// Send the Request in json format on stdin to the callout script
func closeCallout(ctx context.Context, conn *networkservice.Connection) error {
	logrus.Infof("closeCallout")
	cmd := exec.Command(calloutProgram(), "close")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdin)
	go func() {
		defer stdin.Close()
		_ = enc.Encode(conn)
	}()
	if out, err := cmd.Output(); err != nil {
		return err
	} else {
		fmt.Println(string(out))
	}
	return nil
}

// Expect a Mechanism array in json format on stdout from the callout script
func mechanismCallout(ctx context.Context) ([]*networkservice.Mechanism, error) {
	logrus.Infof("mechanismCallout")
	cmd := exec.Command(calloutProgram(), "mechanism")
	out, err := cmd.Output()
	if err != nil {
		logrus.Infof("mechanismCallout err %v", err)
		return nil, err
	}
	fmt.Println(string(out))

	var m []*networkservice.Mechanism
	err = json.Unmarshal(out, &m)
	if err != nil {
		logrus.Infof("mechanismCallout Unmarshal err %v", err)
		return nil, err
	}
	return m, nil
}
