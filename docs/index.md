---
page_title: "Pi-hole Provider"
subcategory: ""
description: |-
  The Pi-hole provider is used to manage Pi-hole configuration objects.
---

# Pi-hole Provider

Use the Pi-hole provider to manage domain allow/deny rules in Pi-hole.

## Example Usage

    provider "pihole" {
      hostname        = "https://10.0.10.10"
      port            = 443
      password        = var.pihole_password
      skip_tls_verify = true
    }

## Schema

### Required

- `hostname` (String) Pi-hole hostname or URL.
- `password` (String, Sensitive) Pi-hole web password.

### Optional

- `port` (Number) Pi-hole API port. Default is `443`.
- `skip_tls_verify` (Boolean) Skip TLS certificate validation for self-signed certificates. Default is `false`.
