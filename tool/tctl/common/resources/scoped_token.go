// Teleport
// Copyright (C) 2026  Gravitational, Inc.
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
package resources

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/gravitational/trace"

	joiningv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/scopes/joining/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/clientutils"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/itertools/stream"
	"github.com/gravitational/teleport/lib/services"
)

type scopedTokenCollection struct {
	tokens []*joiningv1.ScopedToken
}

func NewScopedTokenCollection(tokens []*joiningv1.ScopedToken) Collection {
	return &scopedTokenCollection{
		tokens: tokens,
	}
}

func (c *scopedTokenCollection) Resources() []types.Resource {
	r := make([]types.Resource, len(c.tokens))
	for i, resource := range c.tokens {
		r[i] = types.Resource153ToLegacy(resource)
	}
	return r
}

func (c *scopedTokenCollection) WriteText(w io.Writer, verbose bool) error {
	headers := []string{"Scope", "Name", "Type", "Assigns Scope"}
	rows := make([][]string, len(c.tokens))
	for i, item := range c.tokens {
		rows[i] = []string{
			item.GetScope(),
			item.GetMetadata().GetName(),
			strings.Join(item.GetSpec().GetRoles(), ","),
			item.GetSpec().GetAssignedScope(),
		}
	}

	t := asciitable.MakeTable(headers, rows...)

	_, err := t.AsBuffer().WriteTo(w)
	return trace.Wrap(err)
}

func scopedTokenHandler() Handler {
	return Handler{
		getHandler:    getScopedToken,
		createHandler: createScopedToken,
		deleteHandler: deleteScopedToken,
		description:   "Scoped invitation tokens that can be used to provision resources at a limited scope",
	}
}

func createScopedToken(ctx context.Context, client *authclient.Client, raw services.UnknownResource, opts CreateOpts) error {
	if opts.Force {
		return trace.BadParameter("scoped token creation does not support --force")
	}

	r, err := services.UnmarshalProtoResource[*joiningv1.ScopedToken](raw.Raw, services.DisallowUnknown())
	if err != nil {
		return trace.Wrap(err)
	}

	token, err := client.CreateScopedToken(ctx, r)
	if err != nil {
		return trace.Wrap(err)
	}

	fmt.Printf(
		"%v %q has been created\n",
		types.KindScopedToken,
		token.GetMetadata().GetName(),
	)

	return nil
}

func getScopedToken(ctx context.Context, client *authclient.Client, ref services.Ref, opts GetOpts) (Collection, error) {
	// If a specific token name is requested, filter the results
	if ref.Name != "" {
		token, err := client.GetScopedToken(ctx, ref.Name)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return &scopedTokenCollection{[]*joiningv1.ScopedToken{token}}, nil
	}

	tokens, err := stream.Collect(clientutils.Resources(ctx, func(ctx context.Context, pageSize int, pageKey string) ([]*joiningv1.ScopedToken, string, error) {
		res, err := client.ListScopedTokens(ctx, &joiningv1.ListScopedTokensRequest{
			Limit:  uint32(pageSize),
			Cursor: pageKey,
		})
		if err != nil {
			return nil, "", trace.Wrap(err)
		}

		return res.GetTokens(), res.GetCursor(), nil
	}))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &scopedTokenCollection{tokens: tokens}, nil
}

func deleteScopedToken(ctx context.Context, client *authclient.Client, ref services.Ref) error {
	if err := client.DeleteScopedToken(ctx, ref.Name); err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf(
		"%v %q has been deleted\n",
		types.KindScopedToken,
		ref.Name,
	)
	return nil
}
