//
// Copyright 2024-2025 The Chainloop Authors.
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

package biz

import (
	"os"
	"testing"

	schemav1 "github.com/chainloop-dev/chainloop/app/controlplane/api/workflowcontract/v1"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/unmarshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentifyAndValidateRawContract(t *testing.T) {
	testData := []struct {
		filename          string
		wantFormat        unmarshal.RawFormat
		wantValidationErr bool
		wantFormatErr     bool
	}{
		{
			filename:   "contract.cue",
			wantFormat: unmarshal.RawFormatCUE,
		},
		{
			filename:   "contract.json",
			wantFormat: unmarshal.RawFormatJSON,
		},
		{
			filename:          "invalid_contract.json",
			wantValidationErr: true,
		},
		{
			filename:   "contract.yaml",
			wantFormat: unmarshal.RawFormatYAML,
		},
		{
			filename:          "invalid_contract.yaml",
			wantValidationErr: true,
		},
		{
			filename:      "invalid_format.json",
			wantFormatErr: true,
		},
	}

	for _, tc := range testData {
		t.Run(tc.filename, func(t *testing.T) {
			// load file from testdata/contracts
			data, err := os.ReadFile("testdata/contracts/" + tc.filename)
			require.NoError(t, err)

			contract, err := identifyUnMarshalAndValidateRawContract(data)
			if tc.wantValidationErr {
				assert.Error(t, err)
				assert.True(t, IsErrValidation(err))
				return
			} else if tc.wantFormatErr {
				assert.Error(t, err)
				assert.False(t, IsErrValidation(err))
				return
			}

			require.NoError(t, err)

			assert.Equal(t, tc.wantFormat, contract.Format)
			assert.Equal(t, data, contract.Raw)
		})
	}
}

func TestValidatePolicyKindForAttestationSection(t *testing.T) {
	testCases := []struct {
		name      string
		policy    *schemav1.Policy
		wantError bool
		errMsg    string
	}{
		{
			name: "valid attestation-level policy with kind ATTESTATION",
			policy: &schemav1.Policy{
				Metadata: &schemav1.Metadata{
					Name: "sbom-present",
				},
				Spec: &schemav1.PolicySpec{
					Policies: []*schemav1.PolicySpecV2{
						{
							Kind: schemav1.CraftingSchema_Material_ATTESTATION,
							Source: &schemav1.PolicySpecV2_Embedded{
								Embedded: "package main\nresult := true",
							},
						},
					},
				},
			},
			wantError: false,
		},
		{
			name: "invalid policy with kind UNSPECIFIED in attestation section",
			policy: &schemav1.Policy{
				Metadata: &schemav1.Metadata{
					Name: "generic-policy",
				},
				Spec: &schemav1.PolicySpec{
					Policies: []*schemav1.PolicySpecV2{
						{
							Kind: schemav1.CraftingSchema_Material_MATERIAL_TYPE_UNSPECIFIED,
							Source: &schemav1.PolicySpecV2_Embedded{
								Embedded: "package main\nresult := true",
							},
						},
					},
				},
			},
			wantError: true,
			errMsg:    "must have kind ATTESTATION for attestation section",
		},
		{
			name: "invalid policy with kind SBOM_SPDX_JSON in attestation section",
			policy: &schemav1.Policy{
				Metadata: &schemav1.Metadata{
					Name: "sbom-validation",
				},
				Spec: &schemav1.PolicySpec{
					Policies: []*schemav1.PolicySpecV2{
						{
							Kind: schemav1.CraftingSchema_Material_SBOM_SPDX_JSON,
							Source: &schemav1.PolicySpecV2_Embedded{
								Embedded: "package main\nresult := true",
							},
						},
					},
				},
			},
			wantError: true,
			errMsg:    "must have kind ATTESTATION for attestation section",
		},
		{
			name: "valid policy with multiple kinds including ATTESTATION",
			policy: &schemav1.Policy{
				Metadata: &schemav1.Metadata{
					Name: "multi-kind-policy",
				},
				Spec: &schemav1.PolicySpec{
					Policies: []*schemav1.PolicySpecV2{
						{
							Kind: schemav1.CraftingSchema_Material_SBOM_SPDX_JSON,
							Source: &schemav1.PolicySpecV2_Embedded{
								Embedded: "package main\nresult := true",
							},
						},
						{
							Kind: schemav1.CraftingSchema_Material_ATTESTATION,
							Source: &schemav1.PolicySpecV2_Embedded{
								Embedded: "package main\nresult := true",
							},
						},
					},
				},
			},
			wantError: false,
		},
		{
			name: "legacy policy with deprecated path field - should pass",
			policy: &schemav1.Policy{
				Metadata: &schemav1.Metadata{
					Name: "legacy-path-policy",
				},
				Spec: &schemav1.PolicySpec{
					Source: &schemav1.PolicySpec_Path{
						Path: "file://policy.rego",
					},
				},
			},
			wantError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePolicyKindForAttestationSection(tc.policy)
			if tc.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
