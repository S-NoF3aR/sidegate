# Contributing

Thanks for your interest in Sidegate!

## Developer Certificate of Origin

Sidegate is licensed under the AGPL-3.0 (the Terraform provider under the
MPL-2.0), and contributions are accepted under the same license. Sign off
every commit to certify that you wrote it or otherwise have the right to
submit it under that license, as described in the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "…"   # adds "Signed-off-by: Your Name <you@example.com>"
```

## Development

```sh
make test                    # all tests, with the race detector
docker compose up --build    # local demo, see README.md
```

- Add `// SPDX-License-Identifier: AGPL-3.0-only` to new files
  (`MPL-2.0` in `terraform-provider-sidegate/`).
- New dependencies must have a license compatible with AGPL-3.0 (MIT, BSD,
  ISC, Apache-2.0, MPL-2.0). Run `make notices` to check that every
  dependency has a license file.
