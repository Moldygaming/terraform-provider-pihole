package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

type DomainType string

const (
	DomainTypeAllow DomainType = "allow"
	DomainTypeDeny  DomainType = "deny"
)

type DomainKind string

const (
	DomainKindExact DomainKind = "exact"
	DomainKindRegex DomainKind = "regex"
)

type DomainPathParameters struct {
	Type string
	Kind string
}

type DomainRequestBody struct {
	Domain  DomainInput `json:"domain"`
	Comment *string     `json:"comment"`
	Groups  []int       `json:"groups,omitempty"`
	Enabled *bool       `json:"enabled,omitempty"`
}

type DomainReplaceRequestBody struct {
	Type    DomainType `json:"type"`
	Kind    DomainKind `json:"kind"`
	Comment *string    `json:"comment"`
	Groups  []int      `json:"groups"`
	Enabled bool       `json:"enabled"`
}

// DomainInput represents the oneOf request schema for the "domain" field:
// - a single domain string
// - an array of domain strings
type DomainInput struct {
	Single *string
	Many   []string
}

func NewSingleDomainInput(domain string) DomainInput {
	return DomainInput{Single: &domain}
}

func NewMultiDomainInput(domains []string) DomainInput {
	return DomainInput{Many: domains}
}

func (d DomainInput) Validate() error {
	if d.Single != nil && len(d.Many) > 0 {
		return errors.New("domain input must be either single domain or array of domains, not both")
	}

	if d.Single == nil && len(d.Many) == 0 {
		return errors.New("domain input requires one domain or an array of domains")
	}

	if d.Single != nil && *d.Single == "" {
		return errors.New("single domain cannot be empty")
	}

	for _, item := range d.Many {
		if item == "" {
			return errors.New("domain array cannot contain empty domain values")
		}
	}

	return nil
}

func (d DomainInput) MarshalJSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}

	if d.Single != nil {
		return json.Marshal(*d.Single)
	}

	return json.Marshal(d.Many)
}

func (d *DomainInput) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		d.Single = &single
		d.Many = nil
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		d.Single = nil
		d.Many = many
		return nil
	}

	return fmt.Errorf("domain must be string or []string")
}

type DomainResponse struct {
	Domains   []DomainRecord    `json:"domains"`
	Processed *ProcessedResults `json:"processed"`
	Took      float64           `json:"took"`
}

type DomainRecord struct {
	Domain       string     `json:"domain"`
	Unicode      string     `json:"unicode"`
	Type         DomainType `json:"type"`
	Kind         DomainKind `json:"kind"`
	Comment      *string    `json:"comment"`
	Groups       []int      `json:"groups"`
	Enabled      bool       `json:"enabled"`
	ID           int64      `json:"id"`
	DateAdded    int64      `json:"date_added"`
	DateModified int64      `json:"date_modified"`
}

type ProcessedResults struct {
	Success []ProcessedSuccess `json:"success"`
	Errors  []ProcessedError   `json:"errors"`
}

type ProcessedSuccess struct {
	Item string `json:"item"`
}

type ProcessedError struct {
	Item  string `json:"item"`
	Error string `json:"error"`
}

func resourceDomain() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a Pi-hole domain entry (allow/deny, exact/regex).",
		CreateContext: resourceDomainCreate,
		ReadContext:   resourceDomainRead,
		UpdateContext: resourceDomainUpdate,
		DeleteContext: resourceDomainDelete,
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Domain to manage.",
			},
			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      string(DomainTypeDeny),
				Description:  "Domain type: allow or deny.",
				ValidateFunc: validation.StringInSlice([]string{string(DomainTypeAllow), string(DomainTypeDeny)}, false),
			},
			"kind": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      string(DomainKindExact),
				Description:  "Domain kind: exact or regex.",
				ValidateFunc: validation.StringInSlice([]string{string(DomainKindExact), string(DomainKindRegex)}, false),
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User-provided free-text comment for this domain.",
			},
			"groups": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Array of group IDs.",
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Status of domain.",
			},
			"unicode": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Unicode domain (may differ from domain if punycode is used).",
			},
			"date_added": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Unix timestamp of domain addition.",
			},
			"date_modified": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Unix timestamp of last domain modification.",
			},
		},
	}
}

func resourceDomainCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, ok := meta.(*Client)
	if !ok || client == nil {
		return diag.Errorf("invalid provider client configuration")
	}

	domain := strings.TrimSpace(d.Get("domain").(string))
	if domain == "" {
		return diag.Errorf("domain cannot be empty")
	}

	domainType := d.Get("type").(string)
	domainKind := d.Get("kind").(string)

	requestBody := DomainRequestBody{
		Domain: NewSingleDomainInput(domain),
	}

	if value, ok := d.GetOk("comment"); ok {
		comment := value.(string)
		requestBody.Comment = &comment
	}

	if value, ok := d.GetOk("groups"); ok {
		rawGroups := value.([]interface{})
		groups := make([]int, 0, len(rawGroups))
		for _, item := range rawGroups {
			groups = append(groups, item.(int))
		}
		requestBody.Groups = groups
	}

	if value, ok := d.GetOkExists("enabled"); ok {
		enabled := value.(bool)
		requestBody.Enabled = &enabled
	}

	payload, err := json.Marshal(requestBody)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to encode domain create payload: %w", err))
	}

	endpoint := *client.BaseURL
	endpoint.Path = path.Join(endpoint.Path, "/api", "domains", domainType, domainKind)

	if client.SessionToken != "" {
		query := endpoint.Query()
		query.Set("sid", client.SessionToken)
		endpoint.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to create domain request: %w", err))
	}

	req.Header.Set("Content-Type", "application/json")
	if client.SessionToken != "" {
		req.Header.Set("X-FTL-SID", client.SessionToken)
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to create domain: %w", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read domain create response: %w", err))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := parseDomainCreateError(body)
		if isDuplicateDomainError(msg) {
			return diag.Errorf("domain %q (%s/%s) already exists: %s", domain, domainType, domainKind, msg)
		}
		return diag.Errorf("domain create failed with status %d: %s", resp.StatusCode, msg)
	}

	var result DomainResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &result); err != nil {
			return diag.FromErr(fmt.Errorf("failed to decode domain create response: %w", err))
		}
	}

	if result.Processed != nil && len(result.Processed.Errors) > 0 {
		first := result.Processed.Errors[0]
		if isDuplicateDomainError(first.Error) {
			return diag.Errorf("domain %q (%s/%s) already exists: %s", domain, domainType, domainKind, first.Error)
		}
		return diag.Errorf("domain create failed for %q: %s", first.Item, first.Error)
	}

	d.SetId(buildDomainResourceID(domainType, domainKind, domain))

	if record := findDomainRecord(result.Domains, domain, domainType, domainKind); record != nil {
		_ = d.Set("domain", record.Domain)
		_ = d.Set("type", string(record.Type))
		_ = d.Set("kind", string(record.Kind))
		_ = d.Set("comment", record.Comment)
		_ = d.Set("groups", record.Groups)
		_ = d.Set("enabled", record.Enabled)
		_ = d.Set("unicode", record.Unicode)
		_ = d.Set("date_added", int(record.DateAdded))
		_ = d.Set("date_modified", int(record.DateModified))
	}

	return resourceDomainRead(ctx, d, meta)
}

func findDomainRecord(records []DomainRecord, domain string, domainType string, domainKind string) *DomainRecord {
	for i := range records {
		item := records[i]
		if item.Domain == domain && string(item.Type) == domainType && string(item.Kind) == domainKind {
			return &records[i]
		}
	}

	if len(records) == 1 {
		return &records[0]
	}

	return nil
}

func parseDomainCreateError(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "empty response body"
	}

	type apiErrorDetail struct {
		Key     string `json:"key"`
		Message string `json:"message"`
	}
	type apiErrorResponse struct {
		Error *apiErrorDetail `json:"error"`
	}

	var parsed apiErrorResponse
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Error != nil {
		if parsed.Error.Key != "" && parsed.Error.Message != "" {
			return fmt.Sprintf("%s: %s", parsed.Error.Key, parsed.Error.Message)
		}
		if parsed.Error.Message != "" {
			return parsed.Error.Message
		}
	}

	return trimmed
}

func isDuplicateDomainError(msg string) bool {
	lowered := strings.ToLower(msg)
	return strings.Contains(lowered, "unique constraint failed") || strings.Contains(lowered, "already exists")
}

func resourceDomainRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, ok := meta.(*Client)
	if !ok || client == nil {
		return diag.Errorf("invalid provider client configuration")
	}

	currentType, currentKind, currentDomain, err := splitDomainResourceID(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("invalid domain resource id %q: %w", d.Id(), err))
	}

	endpoint := *client.BaseURL
	endpoint.Path = path.Join(
		endpoint.Path,
		"/api",
		"domains",
		currentType,
		currentKind,
		url.PathEscape(currentDomain),
	)

	if client.SessionToken != "" {
		query := endpoint.Query()
		query.Set("sid", client.SessionToken)
		endpoint.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to create domain read request: %w", err))
	}

	if client.SessionToken != "" {
		req.Header.Set("X-FTL-SID", client.SessionToken)
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read domain: %w", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read domain response body: %w", err))
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return diag.Errorf("domain read failed with status %d: %s", resp.StatusCode, parseDomainCreateError(body))
	}

	var result DomainResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &result); err != nil {
			return diag.FromErr(fmt.Errorf("failed to decode domain read response: %w", err))
		}
	}

	record := findDomainRecord(result.Domains, currentDomain, currentType, currentKind)
	if record == nil {
		d.SetId("")
		return nil
	}

	if err := d.Set("domain", record.Domain); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("type", string(record.Type)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("kind", string(record.Kind)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("comment", record.Comment); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("groups", record.Groups); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("enabled", record.Enabled); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("unicode", record.Unicode); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("date_added", int(record.DateAdded)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("date_modified", int(record.DateModified)); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(buildDomainResourceID(string(record.Type), string(record.Kind), record.Domain))

	return nil
}

func resourceDomainUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, ok := meta.(*Client)
	if !ok || client == nil {
		return diag.Errorf("invalid provider client configuration")
	}

	currentType, currentKind, currentDomain, err := splitDomainResourceID(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("invalid domain resource id %q: %w", d.Id(), err))
	}

	desiredType := d.Get("type").(string)
	desiredKind := d.Get("kind").(string)

	var comment *string
	if value, ok := d.GetOk("comment"); ok {
		c := value.(string)
		comment = &c
	}

	reqBody := DomainReplaceRequestBody{
		Type:    DomainType(desiredType),
		Kind:    DomainKind(desiredKind),
		Comment: comment,
		Groups:  expandIntList(d.Get("groups").([]interface{})),
		Enabled: d.Get("enabled").(bool),
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to encode domain update payload: %w", err))
	}

	endpoint := *client.BaseURL
	endpoint.Path = path.Join(
		endpoint.Path,
		"/api",
		"domains",
		currentType,
		currentKind,
		url.PathEscape(currentDomain),
	)

	if client.SessionToken != "" {
		query := endpoint.Query()
		query.Set("sid", client.SessionToken)
		endpoint.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to create domain update request: %w", err))
	}

	req.Header.Set("Content-Type", "application/json")
	if client.SessionToken != "" {
		req.Header.Set("X-FTL-SID", client.SessionToken)
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to update domain: %w", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read domain update response: %w", err))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return diag.Errorf("domain update failed with status %d: %s", resp.StatusCode, parseDomainCreateError(body))
	}

	d.SetId(buildDomainResourceID(desiredType, desiredKind, currentDomain))

	if err := d.Set("type", desiredType); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("kind", desiredKind); err != nil {
		return diag.FromErr(err)
	}

	return resourceDomainRead(ctx, d, meta)
}

func resourceDomainDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, ok := meta.(*Client)
	if !ok || client == nil {
		return diag.Errorf("invalid provider client configuration")
	}

	currentType, currentKind, currentDomain, err := splitDomainResourceID(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("invalid domain resource id %q: %w", d.Id(), err))
	}

	endpoint := *client.BaseURL
	endpoint.Path = path.Join(
		endpoint.Path,
		"/api",
		"domains",
		currentType,
		currentKind,
		url.PathEscape(currentDomain),
	)

	if client.SessionToken != "" {
		query := endpoint.Query()
		query.Set("sid", client.SessionToken)
		endpoint.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to create domain delete request: %w", err))
	}

	if client.SessionToken != "" {
		req.Header.Set("X-FTL-SID", client.SessionToken)
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to delete domain: %w", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read domain delete response: %w", err))
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return diag.Errorf("domain delete failed with status %d: %s", resp.StatusCode, parseDomainCreateError(body))
	}

	d.SetId("")
	return nil
}

func expandIntList(input []interface{}) []int {
	if len(input) == 0 {
		return []int{}
	}

	result := make([]int, 0, len(input))
	for _, item := range input {
		result = append(result, item.(int))
	}

	return result
}

func buildDomainResourceID(domainType string, domainKind string, domain string) string {
	return fmt.Sprintf("%s/%s/%s", domainType, domainKind, url.PathEscape(domain))
}

func splitDomainResourceID(id string) (string, string, string, error) {
	parts := strings.Split(id, "/")
	if len(parts) < 3 {
		return "", "", "", errors.New("expected id format type/kind/domain")
	}

	domainType := parts[0]
	domainKind := parts[1]
	rawDomain := strings.Join(parts[2:], "/")

	unescaped, err := url.PathUnescape(rawDomain)
	if err == nil {
		return domainType, domainKind, unescaped, nil
	}

	return domainType, domainKind, rawDomain, nil
}
