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

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/grpcfd"
	"github.com/kelseyhightower/envconfig"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	vlanmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vlan"
	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	registryclient "github.com/networkservicemesh/sdk/pkg/registry/chains/client"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/singlepointipam"

	"github.com/Nordix/nsm-nse-generic/internal/pkg/networkservice/vlanmapserver"
)

const (
	tcpSchema = "tcp"
)

type Config struct {
	Name             string            `default:"vlan-server" desc:"Name of the endpoint"`
	ConnectTo        url.URL           `default:"nsm-registry-svc:5002" desc:"url of registry service to connect to" split_words:"true"`
	MaxTokenLifetime time.Duration     `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`
	ServiceNames     []string          `default:"nse-vlan" desc:"Name of providing services" split_words:"true"`
	Payload          string            `default:"ETHERNET" desc:"Name of provided service payload" split_words:"true"`
	Labels           map[string]string `default:"" desc:"Endpoint labels"`
	CidrPrefix       string            `default:"169.254.0.0/16" desc:"CIDR Prefix to assign IPs from" split_words:"true"`
	Ipv6Prefix       string            `default:"" desc:"Ipv6 Prefix for dual-stack" split_words:"true"`
	VlanBaseIfname   string            `default:"" desc:"Base interface name for vlan interface" split_words:"true"`
	VlanId           int32             `default:"" desc:"Vlan ID for vlan interface" split_words:"true"`
	RegisterService  bool              `default:"true" desc:"if true then registers network service on startup" split_words:"true"`
	ListenOn         url.URL           `default:"tcp://:5003" desc:"tcp:// url to be listen on. It will be used as public to register NSM" split_words:"true"`
}

// processConfig prints and processes env to config
func processConfig() *Config {
	c := new(Config)
	if err := envconfig.Usage("nsm", c); err != nil {
		logrus.Fatal(err)
	}
	if err := envconfig.Process("nsm", c); err != nil {
		logrus.Fatalf("cannot process envconfig nse %+v", err)
	}
	return c
}

func validateConfig(cfg *Config) error {

	if cfg.ListenOn.Scheme != tcpSchema {
		return errors.New("only tcp schema is supported for this type of endpoint")
	}
	// vlan ID range is 0 to 4,095
	if cfg.VlanBaseIfname != "" && (cfg.VlanId < 1 || cfg.VlanId > 4095) {
		return errors.New("invalid vlan ID")
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
	logger.Infof("3: parse network prefixes for ipam")
	logger.Infof("4: create network service endpoint")
	logger.Infof("5: create grpc server and register the server")
	logger.Infof("6: register nse with nsm")
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
	log.FromContext(ctx).Infof("executing phase 3: parsing network prefixes for ipam")
	// ********************************************************************************

	_, ipNet1, err := net.ParseCIDR(config.CidrPrefix)
	if err != nil {
		logrus.Fatalf("Could not parse cidr %s; %+v", config.CidrPrefix, err)
	}

	var ipamChain networkservice.NetworkServiceServer

	if config.Ipv6Prefix != "" {
		_, ipNet2, err := net.ParseCIDR(config.Ipv6Prefix)
		if err != nil {
			log.FromContext(ctx).Fatalf("error parsing cidr: %+v", err)
		}
		ipamChain = chain.NewNetworkServiceServer(
			singlepointipam.NewServer(ipNet1),
			singlepointipam.NewServer(ipNet2),
		)
	} else {
		ipamChain = chain.NewNetworkServiceServer(singlepointipam.NewServer(ipNet1))
	}
	// ********************************************************************************
	logger.Infof("executing phase 4: create network service endpoint")
	// ********************************************************************************
	responderEndpoint := endpoint.NewServer(ctx,
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		endpoint.WithName(config.Name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			ipamChain,
			recvfd.NewServer(),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				vlanmech.MECHANISM: vlanmapserver.NewServer(config.VlanBaseIfname, config.VlanId),
			}),
			sendfd.NewServer()))

	// ********************************************************************************
	logger.Infof("executing phase 5: create grpc server and register the server")
	// ********************************************************************************
	serverCreds := grpc.Creds(
		grpcfd.TransportCredentials(
			credentials.NewTLS(
				tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny()),
			),
		),
	)

	options := append(
		opentracing.WithTracing(),
		serverCreds)
	server := grpc.NewServer(options...)
	responderEndpoint.Register(server)

	listenOn := &config.ListenOn
	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)

	logger.Infof("grpc server started")

	// ********************************************************************************
	logger.Infof("executing phase 6: register nse with nsm")
	// ********************************************************************************

	clientOptions := append(
		opentracing.WithTracingDial(),
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

	if config.RegisterService {
		for _, serviceName := range config.ServiceNames {
			nsRegistryClient := registryclient.NewNetworkServiceRegistryClient(ctx, &config.ConnectTo, registryclient.WithDialOptions(clientOptions...))
			_, err = nsRegistryClient.Register(ctx, &registryapi.NetworkService{
				Name:    serviceName,
				Payload: config.Payload,
			})

			if err != nil {
				log.FromContext(ctx).Fatalf("unable to register ns %+v", err)
			}
		}
	}

	nseRegistryClient := registryclient.NewNetworkServiceEndpointRegistryClient(ctx, &config.ConnectTo, registryclient.WithDialOptions(clientOptions...))
	nse := &registryapi.NetworkServiceEndpoint{
		Name:                 config.Name,
		NetworkServiceNames:  config.ServiceNames,
		NetworkServiceLabels: make(map[string]*registryapi.NetworkServiceLabels),
		Url:                  getPublicURL(listenOn),
	}
	for _, serviceName := range config.ServiceNames {
		nse.NetworkServiceLabels[serviceName] = &registryapi.NetworkServiceLabels{Labels: config.Labels}
	}
	nse, err = nseRegistryClient.Register(ctx, nse)
	logrus.Infof("nse: %+v", nse)

	if err != nil {
		log.FromContext(ctx).Fatalf("unable to register nse %+v", err)
	}
	//}

	// ********************************************************************************
	logger.Infof("startup completed in %v", time.Since(starttime))
	// ********************************************************************************
	// wait for server to exit
	<-ctx.Done()
}

func getPublicURL(u *url.URL) string {
	if u.Port() == "" || len(u.Host) != len(":")+len(u.Port()) {
		return u.String()
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		logrus.Warn(err.Error())
		return u.String()
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return fmt.Sprintf("%v://%v:%v", tcpSchema, ipnet.IP.String(), u.Port())
			}
		}
	}
	return u.String()
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
