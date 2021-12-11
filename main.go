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
	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	vlanmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vlan"
	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"
	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/singlepointipam"
	registryclient "github.com/networkservicemesh/sdk/pkg/registry/chains/client"
	"github.com/networkservicemesh/sdk/pkg/tools/debug"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/jaeger"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/opentracing"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"

	"github.com/Nordix/nsm-nse-generic/internal/pkg/config"
	"github.com/Nordix/nsm-nse-generic/internal/pkg/networkservice/vlanmapserver"
)

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
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[0]}))

	if err := debug.Self(); err != nil {
		log.FromContext(ctx).Infof("%s", err)
	}
	logger := log.FromContext(ctx)

	// ********************************************************************************
	// Configure open tracing
	// ********************************************************************************
	log.EnableTracing(true)
	jaegerCloser := jaeger.InitJaeger(ctx, "cmd-nse-vlan")
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
	cfg := new(config.Config)
	if err := cfg.Process(); err != nil {
		logrus.Fatal(err.Error())
	}

	log.FromContext(ctx).Infof("Config: %#v", cfg)

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

	_, ipNet1, err := net.ParseCIDR(cfg.CidrPrefix)
	if err != nil {
		logrus.Fatalf("Could not parse cidr %s; %+v", cfg.CidrPrefix, err)
	}

	var ipamChain networkservice.NetworkServiceServer

	if cfg.Ipv6Prefix != "" {
		_, ipNet2, err := net.ParseCIDR(cfg.Ipv6Prefix)
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
		spiffejwt.TokenGeneratorFunc(source, cfg.MaxTokenLifetime),
		endpoint.WithName(cfg.Name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			ipamChain,
			recvfd.NewServer(),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				vlanmech.MECHANISM: vlanmapserver.NewServer(cfg),
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

	listenOn := &cfg.ListenOn
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

	if cfg.RegisterService {

		nsRegistryClient := registryclient.NewNetworkServiceRegistryClient(ctx, &cfg.ConnectTo, registryclient.WithDialOptions(clientOptions...))
		for i := range cfg.Services {
			nsName := cfg.Services[i].Name
			nsPayload := payload.Ethernet
			if _, err = nsRegistryClient.Register(ctx, &registryapi.NetworkService{
				Name:    nsName,
				Payload: nsPayload,
			}); err != nil {
				log.FromContext(ctx).Fatalf("failed to register ns(%s) %s", nsName, err.Error())
			}
		}

	}

	nseRegistryClient := registryclient.NewNetworkServiceEndpointRegistryClient(ctx, &cfg.ConnectTo, registryclient.WithDialOptions(clientOptions...))
	nse := getNseEndpoint(listenOn, cfg)

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
				return fmt.Sprintf("tcp://%v:%v", ipnet.IP.String(), u.Port())
			}
		}
	}
	return u.String()
}

func getNseEndpoint(listenOn *url.URL, cfg *config.Config) *registryapi.NetworkServiceEndpoint {
	expireTime, _ := ptypes.TimestampProto(time.Now().Add(cfg.MaxTokenLifetime))

	nse := &registryapi.NetworkServiceEndpoint{
		Name:                 cfg.Name,
		NetworkServiceNames:  make([]string, len(cfg.Services)),
		NetworkServiceLabels: make(map[string]*registryapi.NetworkServiceLabels, len(cfg.Services)),
		Url:                  getPublicURL(listenOn),
		ExpirationTime:       expireTime,
	}

	for i := range cfg.Services {
		service := &cfg.Services[i]

		labels := service.Labels
		if labels == nil {
			labels = make(map[string]string, 1)
		}
		nse.NetworkServiceNames[i] = service.Name
		nse.NetworkServiceLabels[service.Name] = &registryapi.NetworkServiceLabels{
			Labels: labels,
		}
	}
	return nse
}
