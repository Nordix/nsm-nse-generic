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

package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"

	"github.com/Nordix/nsm-nse-generic/internal/pkg/config"
)

func TestServiceConfig_UnmarshalBinary(t *testing.T) {
	cfg := new(config.ServiceConfig)

	err := cfg.UnmarshalBinary([]byte("finance-bridge@service-domain.2: { vlan: 100 }"))
	require.NoError(t, err)

	require.Equal(t, &config.ServiceConfig{
		Name:    "finance-bridge",
		Domain:  "service-domain.2",
		Payload: payload.Ethernet,
		VLANTag: 100,
	}, cfg)

	err = cfg.UnmarshalBinary([]byte("finance-bridge@service-domain.1: { vlan: 200; payload: IP }"))
	require.NoError(t, err)

	require.Equal(t, &config.ServiceConfig{
		Name:    "finance-bridge",
		Domain:  "service-domain.1",
		Payload: payload.IP,
		VLANTag: 200,
	}, cfg)
}
