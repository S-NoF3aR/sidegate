// SPDX-License-Identifier: MPL-2.0

// Package provider implements the sidegate Terraform provider.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/s-nof3ar/sidegate/terraform-provider-sidegate/internal/client"
)

type sidegateProvider struct {
	version string
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &sidegateProvider{version: version} }
}

func (p *sidegateProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sidegate"
	resp.Version = p.version
}

func (p *sidegateProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages apps and group names of a Sidegate identity-aware proxy.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Description: "Public URL of the proxy portal, e.g. https://apps.example.com. Defaults to $SIDEGATE_ENDPOINT.",
				Optional:    true,
			},
			"token": schema.StringAttribute{
				Description: "API token created in the admin UI (API tokens tab). Defaults to $SIDEGATE_TOKEN.",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

func (p *sidegateProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.Endpoint.IsUnknown() || cfg.Token.IsUnknown() {
		// Values depend on other resources; Terraform calls Configure
		// again once they are known.
		return
	}
	endpoint := os.Getenv("SIDEGATE_ENDPOINT")
	if !cfg.Endpoint.IsNull() {
		endpoint = cfg.Endpoint.ValueString()
	}
	token := os.Getenv("SIDEGATE_TOKEN")
	if !cfg.Token.IsNull() {
		token = cfg.Token.ValueString()
	}
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Missing endpoint",
			"Set the endpoint attribute or the SIDEGATE_ENDPOINT environment variable.")
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("token"), "Missing token",
			"Set the token attribute or the SIDEGATE_TOKEN environment variable. Create a token in the admin UI under API tokens.")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	c := client.New(endpoint, token, p.version)
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *sidegateProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newAppResource, newGroupResource}
}

func (p *sidegateProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}

// clientFrom extracts the API client passed by Configure.
func clientFrom(data any, diags interface{ AddError(string, string) }) *client.Client {
	if data == nil {
		return nil // provider not configured yet (e.g. during validation)
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data", "This is a bug in the provider.")
	}
	return c
}
