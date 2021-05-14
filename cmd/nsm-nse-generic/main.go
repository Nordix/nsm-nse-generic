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
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/Nordix/simple-ipam/pkg/ipam"
	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/grpcfd"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/kelseyhightower/envconfig"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	vlanmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vlan"
	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk-kernel/pkg/kernel/networkservice/common/mechanisms/vlan"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	registryclient "github.com/networkservicemesh/sdk/pkg/registry/chains/client"
	registryrefresh "github.com/networkservicemesh/sdk/pkg/registry/common/refresh"
	registrysendfd "github.com/networkservicemesh/sdk/pkg/registry/common/sendfd"
	registrychain "github.com/networkservicemesh/sdk/pkg/registry/core/chain"
	"github.com/networkservicemesh/sdk/pkg/tools/debug"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/jaeger"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/opentracing"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	meridioipam "github.com/nordix/meridio/pkg/ipam"
)

type Config struct {
	Name             string            `default:"vlan-server" desc:"Name of the endpoint"`
	ConnectTo        url.URL           `default:"unix:///var/lib/networkservicemesh/nsm.io.sock" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime time.Duration     `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`
	ServiceName      string            `default:"nse-vlan" desc:"Name of providing service" split_words:"true"`
	Payload          string            `default:"ETHERNET" desc:"Name of provided service payload" split_words:"true"`
	Labels           map[string]string `default:"" desc:"Endpoint labels"`
	CidrPrefix       string            `default:"169.254.0.0/16" desc:"CIDR Prefix to assign IPs from" split_words:"true"`
	Ipv6Prefix       string            `default:"" desc:"Ipv6 Prefix for dual-stack" split_words:"true"`
	Point2Point      bool              `default:"True" desc:"Use /32 or /128 addresses" split_words:"false"`
	MeridioIpam      string            `default:"" desc:"Example: meridio-ipam:7777" split_words:"true"`
	VlanBaseIfname   string            `default:"" desc:"Base interface name for vlan interface" split_words:"true"`
	VlanId           int32             `default:"" desc:"Vlan ID for vlan interface" split_words:"true"`
}

// processConfig prints and processes env to config
func processConfig() *Config {
	c := new(Config)
	if err := envconfig.Usage("nse", c); err != nil {
		logrus.Fatal(err)
	}
	if err := envconfig.Process("nse", c); err != nil {
		logrus.Fatalf("cannot process envconfig nse %+v", err)
	}
	return c
}

func validateConfig(cfg *Config) error {
	// vlan ID range is 0 to 4,095
	if cfg.VlanBaseIfname != "" && (cfg.VlanId < 1 || cfg.VlanId > 4095) {
		return errors.New("invalid vlan ID")
	}
	if cfg.VlanBaseIfname == "" && cfg.VlanId > 0 {
		return errors.New("base interface is empty")
	}
	return nil
}

func main() {
	// ********************************************************************************
	// setup context to catch signals
	// ********************************************************************************
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// ********************************************************************************
	// setup logging
	// ********************************************************************************
	logrus.SetFormatter(&nested.Formatter{})
	ctx = log.WithFields(ctx, map[string]interface{}{"cmd": os.Args[0]})
	ctx = log.WithLog(ctx, logruslogger.New(ctx))

	if err := debug.Self(); err != nil {
		log.FromContext(ctx).Infof("%s", err)
	}
	logger := log.FromContext(ctx)

	// ********************************************************************************
	// Configure open tracing
	// ********************************************************************************
	log.EnableTracing(true)
	jaegerCloser := jaeger.InitJaeger(ctx, "cmd-nse-vfio")
	defer func() { _ = jaegerCloser.Close() }()

	// enumerating phases
	logger.Infof("there are 4 phases which will be executed followed by a success message:")
	logger.Infof("the phases include:")
	logger.Infof("1: get config from environment")
	logger.Infof("2: retrieve spiffe svid")
	logger.Infof("3: create network service endpoint")
	logger.Infof("4: create grpc server and register the server")
	logger.Infof("5: register nse with nsm")
	starttime := time.Now()

	// ********************************************************************************
	logger.Infof("executing phase 1: get config from environment")
	// ********************************************************************************
	config := processConfig()
	if err := validateConfig(config); err != nil {
		logrus.Fatalf("configuration validation failed %v", err.Error())
	}
	logger.Infof("Config: %#v", config)

	// ********************************************************************************
	logger.Infof("executing phase 2: retrieving svid, check spire agent logs if this is the last line you see")
	// ********************************************************************************
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		logger.Fatalf("error getting x509 source: %v", err.Error())
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		logger.Fatalf("error getting x509 svid: %v", err.Error())
	}
	logger.Infof("sVID: %q", svid.ID)

	// ********************************************************************************
	logger.Infof("executing phase 3: create network service endpoint")
	// ********************************************************************************
	responderEndpoint := endpoint.NewServer(ctx,
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		endpoint.WithName(config.Name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			newSimpleIpam(config),
			recvfd.NewServer(),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				kernelmech.MECHANISM: kernel.NewServer(),
				vlanmech.MECHANISM:   vlan.NewServer(config.VlanBaseIfname, config.VlanId),
			}),
			sendfd.NewServer()))

	// ********************************************************************************
	logger.Infof("executing phase 4: create grpc server and register the server")
	// ********************************************************************************
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

	options := append(
		opentracing.WithTracing(),
		serverCreds)
	server := grpc.NewServer(options...)
	responderEndpoint.Register(server)
	listenOn := &(url.URL{Scheme: "unix", Path: "/tmp/listen.on"})
	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)

	logger.Infof("grpc server started")

	// ********************************************************************************
	logger.Infof("executing phase 5: register nse with nsm")
	// ********************************************************************************
	cc, err := grpc.DialContext(ctx,
		grpcutils.URLToTarget(&config.ConnectTo),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		clientCreds,
	)
	if err != nil {
		logger.Fatalf("error establishing grpc connection to registry server %+v", err)
	}

	_, err = registryclient.NewNetworkServiceRegistryClient(cc).Register(context.Background(), &registryapi.NetworkService{
		Name:    config.ServiceName,
		Payload: config.Payload,
	})

	if err != nil {
		logger.Fatalf("unable to register ns %+v", err)
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

	if err != nil {
		logger.Fatalf("unable to register nse %+v", err)
	}
	logrus.Infof("nse: %+v", nse)
	// ********************************************************************************
	logger.Infof("startup completed in %v", time.Since(starttime))
	// ********************************************************************************
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
		_, err = netlink.ParseAddr(config.CidrPrefix)
		if err != nil {
			logrus.Fatalf("Error Parsing subnet pool")
		}
		proxySubnet, err := ipamClient.AllocateSubnet(config.CidrPrefix, 24)
		if err != nil {
			logrus.Fatalf("Error AllocateSubnet: %+v", err)
		}
		logrus.Infof("Using MeridioIpam cidr; %s", proxySubnet)
		sipam.ipam, err = ipam.New(proxySubnet)
		if err != nil {
			logrus.Fatalf("Could not create ipam for %s; %+v", config.CidrPrefix, err)
		}
	} else {
		sipam.ipam, err = ipam.New(config.CidrPrefix)
		if err != nil {
			logrus.Fatalf("Could not create ipam for %s; %+v", config.CidrPrefix, err)
		}
	}
	sipam.ipam.ReserveFirstAndLast()
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
			ipContext.SrcIpAddrs = []string{addr.String() + mask}
			ipContext.DstRoutes = []*networkservice.Route{
				{
					Prefix: addr.String() + mask,
				},
			}
		}

		if addr, err := s.ipam.Allocate(); err != nil {
			return nil, err
		} else {
			ipContext.DstIpAddrs = []string{addr.String() + mask}
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
	ipContext.SrcIpAddrs = []string{s.myIP}
	if addr, err := s.ipam.Allocate(); err != nil {
		return nil, err
	} else {
		ipContext.DstIpAddrs = []string{addr.String() + mask}
	}

	return next.Server(ctx).Request(ctx, request)
}
func (s *simpleIpam) Close(
	ctx context.Context, conn *networkservice.Connection) (_ *empty.Empty, err error) {
	// TODO free addresses here?
	return next.Server(ctx).Close(ctx, conn)
}
