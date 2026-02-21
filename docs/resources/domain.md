---
page_title: "pihole_domain Resource"
subcategory: ""
description: |-
  Manages Pi-hole domain entries (allow/deny, exact/regex).
---

# pihole_domain

Manages a Pi-hole domain entry.

## Example Usage

resource "pihole_domain" "deny_ads" {
  domain  = "doubleclick.net"
  type    = "deny"
  kind    = "exact"
  comment = "Blocked ad domain"
  groups  = [0]
  enabled = true
}

resource "pihole_domain" "allow_regex" {
  domain = "(^|\\.)example\\.org$"
  type   = "allow"
  kind   = "regex"
}

## Schema

### Required

- `domain` (String) Domain to manage.

### Optional

- `type` (String) Domain type. Allowed values: `allow`, `deny`. Default is `deny`.
- `kind` (String) Domain kind. Allowed values: `exact`, `regex`. Default is `exact`.
- `comment` (String) User-provided free-text comment for this domain.
- `groups` (List of Number) Array of group IDs.
- `enabled` (Boolean) Status of domain. Default is `true`.

### Read-Only

- `unicode` (String) Unicode domain (may differ from `domain` if punycode is used).
- `date_added` (Number) Unix timestamp of domain addition.
- `date_modified` (Number) Unix timestamp of last domain modification.

## Import

Import is supported using `type/kind/domain`.

For example:

```terraform
import {
  to = pihole_domain.deny_ads
  id = "deny/exact/doubleclick.net"
}
```

For regex domains, use URI-escaped values in import IDs.
