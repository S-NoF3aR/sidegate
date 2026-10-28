// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/s-nof3ar/sidegate/terraform-provider-sidegate/internal/client"
)

var (
	appNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	subdomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// The server lower-cases and trims users; requiring that up front keeps
	// the applied value identical to the configured one.
	normalizedUser = regexp.MustCompile(`^[^A-Z\s]+$`)
	noSpace        = regexp.MustCompile(`^\S+$`)
)

type appResource struct {
	client *client.Client
}

type appModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Subdomain          types.String `tfsdk:"subdomain"`
	URL                types.String `tfsdk:"url"`
	Upstream           types.String `tfsdk:"upstream"`
	Title              types.String `tfsdk:"title"`
	Description        types.String `tfsdk:"description"`
	Icon               types.String `tfsdk:"icon"`
	Category           types.String `tfsdk:"category"`
	Public             types.Bool   `tfsdk:"public"`
	Hidden             types.Bool   `tfsdk:"hidden"`
	AllowedGroups      types.Set    `tfsdk:"allowed_groups"`
	AllowedUsers       types.Set    `tfsdk:"allowed_users"`
	PublicPaths        types.Set    `tfsdk:"public_paths"`
	PassHostHeader     types.Bool   `tfsdk:"pass_host_header"`
	HostHeader         types.String `tfsdk:"host_header"`
	InsecureSkipVerify types.Bool   `tfsdk:"insecure_skip_verify"`
	RequireMFA         types.Bool   `tfsdk:"require_mfa"`
	MaxAuthAgeMinutes  types.Int64  `tfsdk:"max_auth_age_minutes"`
}

var (
	_ resource.ResourceWithImportState    = (*appResource)(nil)
	_ resource.ResourceWithValidateConfig = (*appResource)(nil)
	_ resource.ResourceWithImportState    = (*groupResource)(nil)
)

func newAppResource() resource.Resource { return &appResource{} }

func (r *appResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_app"
}

func (r *appResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	emptySet := setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{}))
	optionalString := func(desc string, validators ...validator.String) schema.StringAttribute {
		return schema.StringAttribute{Description: desc, Optional: true, Computed: true, Default: stringdefault.StaticString(""), Validators: validators}
	}
	optionalBool := func(desc string) schema.BoolAttribute {
		return schema.BoolAttribute{Description: desc, Optional: true, Computed: true, Default: booldefault.StaticBool(false)}
	}
	resp.Schema = schema.Schema{
		Description: "An application exposed through the proxy on its own subdomain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "Same as name.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description:   "Unique key of the app. Changing it replaces the app.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{stringvalidator.RegexMatches(appNameRe, "must be 1-63 letters, digits, '.', '_' or '-'")},
			},
			"subdomain": schema.StringAttribute{
				Description:   "Subdomain of the proxy domain the app is served at. Defaults to the lower-cased name.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{subdomainDefault{}},
				Validators:    []validator.String{stringvalidator.RegexMatches(subdomainRe, "must be a lower-case DNS label")},
			},
			"url": schema.StringAttribute{
				Description: "Public URL of the app.",
				Computed:    true,
			},
			"upstream": schema.StringAttribute{
				Description: "URL requests are proxied to, e.g. http://grafana.monitoring.svc:3000.",
				Required:    true,
				Validators:  []validator.String{stringvalidator.RegexMatches(noSpace, "must not contain whitespace")},
			},
			"title":       optionalString("Title shown in the portal."),
			"description": optionalString("Description shown in the portal."),
			"icon":        optionalString("Image URL or a short text such as an emoji."),
			"category": optionalString("Groups the app in the portal; \"/\" nests categories, e.g. \"Monitoring/Logs\". Empty means \"Other\".",
				normalizedCategory{}),
			"public": optionalBool("Proxy without any authentication."),
			"hidden": optionalBool("Reachable but not listed in the portal."),
			"allowed_groups": schema.SetAttribute{
				Description: "IdP group IDs whose members may open the app; \"*\" allows every signed-in user.",
				ElementType: types.StringType, Optional: true, Computed: true, Default: emptySet,
				Validators: []validator.Set{setvalidator.ValueStringsAre(stringvalidator.RegexMatches(noSpace, "must not contain whitespace"))},
			},
			"allowed_users": schema.SetAttribute{
				Description: "Email addresses or usernames (lower-case) that may open the app.",
				ElementType: types.StringType, Optional: true, Computed: true, Default: emptySet,
				Validators: []validator.Set{setvalidator.ValueStringsAre(stringvalidator.RegexMatches(normalizedUser, "must be lower-case without whitespace"))},
			},
			"public_paths": schema.SetAttribute{
				Description: "Paths reachable without sign-in: \"/health\" matches exactly, \"/static/*\" everything below /static/.",
				ElementType: types.StringType, Optional: true, Computed: true, Default: emptySet,
				Validators: []validator.Set{setvalidator.ValueStringsAre(stringvalidator.RegexMatches(regexp.MustCompile(`^/\S*$`), "must start with / and contain no whitespace"))},
			},
			"pass_host_header": optionalBool("Send the original Host header to the upstream. Conflicts with host_header."),
			"host_header": optionalString("Custom Host header sent to the upstream, e.g. grafana.internal.example.com. Conflicts with pass_host_header.",
				stringvalidator.RegexMatches(regexp.MustCompile(`^\S*$`), "must not contain whitespace")),
			"insecure_skip_verify": optionalBool("Skip TLS certificate verification for an https upstream."),
			"require_mfa":          optionalBool("Only admit sign-ins with multi-factor authentication; others are sent back to the IdP for a step-up."),
			"max_auth_age_minutes": schema.Int64Attribute{
				Description: "Require a sign-in within this many minutes (0 = off), e.g. 60 for admin consoles.",
				Optional:    true, Computed: true, Default: int64default.StaticInt64(0),
				Validators: []validator.Int64{int64validator.Between(0, 525600)},
			},
		},
	}
}

func (r *appResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var pass types.Bool
	var host types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("pass_host_header"), &pass)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("host_header"), &host)...)
	if pass.ValueBool() && host.ValueString() != "" {
		resp.Diagnostics.AddAttributeError(path.Root("host_header"), "Conflicting Host header settings",
			"Set either pass_host_header = true or host_header, not both.")
	}
	var public, mfa types.Bool
	var age types.Int64
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("public"), &public)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("require_mfa"), &mfa)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("max_auth_age_minutes"), &age)...)
	if public.ValueBool() && (mfa.ValueBool() || age.ValueInt64() > 0) {
		resp.Diagnostics.AddAttributeError(path.Root("public"), "Public app with sign-in requirements",
			"A public app can't require MFA or a recent sign-in.")
	}
}

func (r *appResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *appResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan appModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	app := plan.toClient(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.client.CreateApp(ctx, app)
	if err != nil {
		resp.Diagnostics.AddError("Creating app failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, fromClient(created))...)
}

func (r *appResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state appModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	app, err := r.client.GetApp(ctx, state.Name.ValueString())
	if errors.Is(err, client.ErrNotFound) {
		resp.State.RemoveResource(ctx) // deleted outside Terraform
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading app failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, fromClient(app))...)
}

func (r *appResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan appModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	app := plan.toClient(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	updated, err := r.client.UpdateApp(ctx, app)
	if err != nil {
		resp.Diagnostics.AddError("Updating app failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, fromClient(updated))...)
}

func (r *appResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state appModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteApp(ctx, state.Name.ValueString()); err != nil && !errors.Is(err, client.ErrNotFound) {
		resp.Diagnostics.AddError("Deleting app failed", err.Error())
	}
}

// ImportState imports an existing app by name:
//
//	terraform import sidegate_app.grafana grafana
func (r *appResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

func (m appModel) toClient(ctx context.Context, diags *diag.Diagnostics) client.App {
	strs := func(s types.Set) []string {
		out := []string{}
		if !s.IsNull() && !s.IsUnknown() {
			diags.Append(s.ElementsAs(ctx, &out, false)...)
		}
		return out
	}
	return client.App{
		Name:               m.Name.ValueString(),
		Subdomain:          m.Subdomain.ValueString(),
		Upstream:           m.Upstream.ValueString(),
		Title:              m.Title.ValueString(),
		Description:        m.Description.ValueString(),
		Icon:               m.Icon.ValueString(),
		Category:           m.Category.ValueString(),
		Public:             m.Public.ValueBool(),
		Hidden:             m.Hidden.ValueBool(),
		AllowedGroups:      strs(m.AllowedGroups),
		AllowedUsers:       strs(m.AllowedUsers),
		PublicPaths:        strs(m.PublicPaths),
		PassHostHeader:     m.PassHostHeader.ValueBool(),
		HostHeader:         m.HostHeader.ValueString(),
		InsecureSkipVerify: m.InsecureSkipVerify.ValueBool(),
		RequireMFA:         m.RequireMFA.ValueBool(),
		MaxAuthAgeMinutes:  m.MaxAuthAgeMinutes.ValueInt64(),
	}
}

func fromClient(a *client.App) appModel {
	set := func(v []string) types.Set {
		elems := make([]attr.Value, len(v))
		for i, s := range v {
			elems[i] = types.StringValue(s)
		}
		return types.SetValueMust(types.StringType, elems)
	}
	return appModel{
		ID:                 types.StringValue(a.Name),
		Name:               types.StringValue(a.Name),
		Subdomain:          types.StringValue(a.Subdomain),
		URL:                types.StringValue(a.URL),
		Upstream:           types.StringValue(a.Upstream),
		Title:              types.StringValue(a.Title),
		Description:        types.StringValue(a.Description),
		Icon:               types.StringValue(a.Icon),
		Category:           types.StringValue(a.Category),
		Public:             types.BoolValue(a.Public),
		Hidden:             types.BoolValue(a.Hidden),
		AllowedGroups:      set(a.AllowedGroups),
		AllowedUsers:       set(a.AllowedUsers),
		PublicPaths:        set(a.PublicPaths),
		PassHostHeader:     types.BoolValue(a.PassHostHeader),
		HostHeader:         types.StringValue(a.HostHeader),
		InsecureSkipVerify: types.BoolValue(a.InsecureSkipVerify),
		RequireMFA:         types.BoolValue(a.RequireMFA),
		MaxAuthAgeMinutes:  types.Int64Value(a.MaxAuthAgeMinutes),
	}
}

// normalizedCategory requires the form the server stores ("A/B", single
// spaces, no empty segments), so the applied value equals the configured one.
type normalizedCategory struct{}

func (normalizedCategory) Description(context.Context) string {
	return `segments separated by "/" without surrounding or repeated spaces`
}

func (v normalizedCategory) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (normalizedCategory) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	c := req.ConfigValue.ValueString()
	var segs []string
	for _, seg := range strings.Split(c, "/") {
		if seg = strings.Join(strings.Fields(seg), " "); seg != "" {
			segs = append(segs, seg)
		}
	}
	if norm := strings.Join(segs, "/"); norm != c {
		resp.Diagnostics.AddAttributeError(req.Path, "Category not normalized",
			fmt.Sprintf("Write %q as %q.", c, norm))
	}
}

// subdomainDefault plans the server's default (the lower-cased name) when
// no subdomain is configured, so plans show the real value.
type subdomainDefault struct{}

func (subdomainDefault) Description(context.Context) string {
	return "Defaults to the lower-cased name."
}

func (d subdomainDefault) MarkdownDescription(ctx context.Context) string { return d.Description(ctx) }

func (subdomainDefault) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if !req.ConfigValue.IsNull() {
		return
	}
	var name types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	if name.IsUnknown() || name.IsNull() {
		return
	}
	resp.PlanValue = types.StringValue(strings.ToLower(name.ValueString()))
}
