// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package testlib

import (
	"fmt"
	"time"

	"github.com/gravitational/trace"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accessv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/scopes/access/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
)

func (s *TerraformSuiteOSS) TestScopedRoleAssignment() {
	t := s.T()
	ctx := t.Context()

	checkDestroyed := func(state *terraform.State) error {
		_, err := s.client.GetScopedRoleAssignment(ctx, "test-scoped-role-assignment")
		if !trace.IsNotFound(err) {
			return trace.Errorf("expected not found, actual: %v", err)
		}
		return nil
	}

	name := "teleport_scoped_role_assignment.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: s.terraformProviders,
		CheckDestroy:             checkDestroyed,
		IsUnitTest:               true,
		Steps: []resource.TestStep{
			{
				Config: s.getFixture("scoped_role_assignment_0_create.tf"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(name, "kind", types.KindScopedRoleAssignment),
					resource.TestCheckResourceAttr(name, "scope", "/staging"),
					resource.TestCheckResourceAttr(name, "spec.user", "testuser"),
					resource.TestCheckResourceAttr(name, "spec.assignments.0.role", "test-scoped-role"),
					resource.TestCheckResourceAttr(name, "spec.assignments.0.scope", "/staging/aa"),
				),
			},
			{
				Config:   s.getFixture("scoped_role_assignment_0_create.tf"),
				PlanOnly: true,
			},
		},
	})
}

func (s *TerraformSuiteOSS) TestImportScopedRoleAssignment() {
	t := s.T()
	ctx := t.Context()

	r := "teleport_scoped_role_assignment"
	id := "test_import_scoped_role_assignment"
	name := r + "." + id

	assignment := &accessv1.ScopedRoleAssignment{
		Kind:    types.KindScopedRoleAssignment,
		Version: types.V1,
		Metadata: &headerv1.Metadata{
			Name: id,
		},
		Scope: "/staging",
		Spec: &accessv1.ScopedRoleAssignmentSpec{
			User: "testuser",
			Assignments: []*accessv1.Assignment{
				{
					Role:  "test-scoped-role",
					Scope: "/staging/aa",
				},
			},
		},
	}

	_, err := s.client.CreateScopedRoleAssignment(ctx, assignment)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(t *assert.CollectT) {
		_, err := s.client.GetScopedRoleAssignment(ctx, id)
		require.NoError(t, err)
	}, 5*time.Second, time.Second)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: s.terraformProviders,
		IsUnitTest:               true,
		Steps: []resource.TestStep{
			{
				Config:        fmt.Sprintf("%s\nresource %q %q { }", s.terraformConfig, r, id),
				ResourceName:  name,
				ImportState:   true,
				ImportStateId: id,
				ImportStateCheck: func(state []*terraform.InstanceState) error {
					require.Equal(t, types.KindScopedRoleAssignment, state[0].Attributes["kind"])
					require.Equal(t, "/staging", state[0].Attributes["scope"])
					require.Equal(t, "testuser", state[0].Attributes["spec.user"])
					return nil
				},
			},
		},
	})
}
