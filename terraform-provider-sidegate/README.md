# terraform-provider-sidegate

Manages the apps and group names of a [Sidegate](../README.md) instance
through its management API.

## Install

The provider isn't published to a registry. Build it into Terraform's local
plugin mirror:

```sh
make install            # VERSION=0.1.0 by default
```

`terraform init` then finds `source = "s-nof3ar/sidegate"`. For CI, run
`make install` in the pipeline or copy the binary into the runner's
`~/.terraform.d/plugins/registry.terraform.io/s-nof3ar/sidegate/<version>/<os>_<arch>/`.
To publish it to the Terraform Registry or a private registry, rename the
namespace and release it with GoReleaser as described in HashiCorp's docs.

## Configure

Create an API token in the admin UI (**Admin → API tokens**), then:

```hcl
provider "sidegate" {
  endpoint = "https://apps.example.com"   # or $SIDEGATE_ENDPOINT
  # token  = "..."                       # or $SIDEGATE_TOKEN (recommended)
}
```

## Resources

### `sidegate_app`

| Attribute | | |
|---|---|---|
| `name` | required | Unique key; changing it replaces the app |
| `upstream` | required | e.g. `http://grafana.monitoring.svc:3000`, `rdp://win1:3389?security=nla` for a remote desktop or `ssh://bastion?host-key=…` for SSH |
| `subdomain` | optional | Defaults to the lower-cased name |
| `title`, `description`, `icon` | optional | Portal display; icon is an image URL or emoji |
| `category` | optional | Portal grouping; `/` nests, e.g. `"Monitoring/Logs"` |
| `allowed_groups` | optional set | IdP group IDs; `"*"` = every signed-in user |
| `allowed_users` | optional set | Lower-case emails/usernames |
| `public` | optional bool | No authentication at all |
| `public_paths` | optional set | `"/health"` (exact), `"/static/*"` (prefix) skip sign-in |
| `host_header` | optional | Custom Host sent upstream |
| `pass_host_header` | optional bool | Send the original Host (conflicts with `host_header`) |
| `hidden` | optional bool | Not listed in the portal |
| `insecure_skip_verify` | optional bool | Skip upstream TLS verification |
| `require_mfa` | optional bool | Only admit sign-ins with MFA (step-up otherwise) |
| `max_auth_age_minutes` | optional number | Require a sign-in within N minutes; `0` = off |
| `url` | computed | Public URL of the app |

Import: `terraform import sidegate_app.grafana grafana`

### `sidegate_group`

| Attribute | | |
|---|---|---|
| `group_id` | required | IdP group ID (Entra object ID); changing it replaces the resource |
| `name` | required | Readable, unique name |

Import: `terraform import sidegate_group.devs 33333333-3333-3333-3333-333333333333`

Reference groups from apps to get the dependency order right:

```hcl
allowed_groups = [sidegate_group.devs.group_id]
```

See [`examples/main.tf`](examples/main.tf) for a complete configuration.

## Notes

- Apps and groups changed outside Terraform (admin UI, API) show up as drift
  in the next plan and are reverted on apply.
- Creating a `sidegate_group` for a group ID that already has a name fails
  with an import hint instead of silently taking it over.
- Changes are recorded in the proxy's audit log as `token:<token name>`.

## Development

```sh
make test
# Use a locally built provider without `terraform init`:
cat > ~/.terraformrc <<'RC'
provider_installation {
  dev_overrides { "registry.terraform.io/s-nof3ar/sidegate" = "/path/to/dir/with/binary" }
  direct {}
}
RC
make build
```
