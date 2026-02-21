package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Pi-hole hostname or URL.",
			},
			"port": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     443,
				Description: "Pi-hole API port. Defaults based on scheme when omitted.",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Pi-hole web password.",
			},
			"skip_tls_verify": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Skip TLS certificate validation for self-signed certificates.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"pihole_domain": resourceDomain(),
		},
		ConfigureContextFunc: configure,
	}
}

func configure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	cfg := AuthProvider{
		Hostname:      d.Get("hostname").(string),
		Password:      d.Get("password").(string),
		SkipTLSVerify: d.Get("skip_tls_verify").(bool),
	}

	if value, ok := d.GetOk("port"); ok {
		cfg.Port = value.(int)
	}

	client, err := cfg.Authenticate(ctx)
	if err != nil {
		return nil, diag.FromErr(fmt.Errorf("failed to configure pihole provider: %w", err))
	}

	return client, nil
}
