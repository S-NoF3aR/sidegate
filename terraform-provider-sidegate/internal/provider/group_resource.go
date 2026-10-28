// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/s-nof3ar/sidegate/terraform-provider-sidegate/internal/client"
)

var trimmed = regexp.MustCompile(`^\S(.*\S)?$`)

type groupResource struct {
	client *client.Client
}

type groupModel struct {
	ID      types.String `tfsdk:"id"`
	GroupID types.String `tfsdk:"group_id"`
	Name    types.String `tfsdk:"name"`
}

func newGroupResource() resource.Resource { return &groupResource{} }

func (r *groupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *groupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A readable name for an IdP group ID, shown in the admin UI and sent in X-Forwarded-Groups.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "Same as group_id.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"group_id": schema.StringAttribute{
				Description:   "The group identifier the IdP emits (for Entra ID: the group's object ID). Changing it replaces the resource.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{stringvalidator.RegexMatches(trimmed, "must not be empty or have surrounding whitespace")},
			},
			"name": schema.StringAttribute{
				Description: "Readable, unique name.",
				Required:    true,
				Validators:  []validator.String{stringvalidator.RegexMatches(trimmed, "must not be empty or have surrounding whitespace")},
			},
		},
	}
}

func (r *groupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *groupResource) put(ctx context.Context, plan groupModel, diags interface{ AddError(string, string) }) *groupModel {
	g, err := r.client.PutGroup(ctx, client.Group{ID: plan.GroupID.ValueString(), Name: plan.Name.ValueString()})
	if err != nil {
		diags.AddError("Saving group failed", err.Error())
		return nil
	}
	return &groupModel{ID: types.StringValue(g.ID), GroupID: types.StringValue(g.ID), Name: types.StringValue(g.Name)}
}

func (r *groupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The API upserts, so make sure Terraform doesn't silently take over a
	// group that already has a name.
	if _, err := r.client.GetGroup(ctx, plan.GroupID.ValueString()); err == nil {
		resp.Diagnostics.AddError("Group already exists",
			"Group "+plan.GroupID.ValueString()+" already has a name. Import it with: terraform import <address> "+plan.GroupID.ValueString())
		return
	} else if !errors.Is(err, client.ErrNotFound) {
		resp.Diagnostics.AddError("Reading group failed", err.Error())
		return
	}
	if state := r.put(ctx, plan, &resp.Diagnostics); state != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	}
}

func (r *groupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	g, err := r.client.GetGroup(ctx, state.GroupID.ValueString())
	if errors.Is(err, client.ErrNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading group failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, groupModel{
		ID: types.StringValue(g.ID), GroupID: types.StringValue(g.ID), Name: types.StringValue(g.Name),
	})...)
}

func (r *groupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state := r.put(ctx, plan, &resp.Diagnostics); state != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	}
}

func (r *groupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteGroup(ctx, state.GroupID.ValueString()); err != nil && !errors.Is(err, client.ErrNotFound) {
		resp.Diagnostics.AddError("Deleting group failed", err.Error())
	}
}

// ImportState imports a group by its IdP group ID.
func (r *groupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group_id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
