package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type AuthProvider struct {
	Hostname      string
	Port          int
	Password      string
	SkipTLSVerify bool
}

type authRequest struct {
	Password string `json:"password"`
}

type Client struct {
	BaseURL      *url.URL
	HTTPClient   *http.Client
	SessionToken string
	LegacyAuth   bool
}

func (a AuthProvider) Authenticate(ctx context.Context) (*Client, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}

	baseURL, err := a.baseURL()
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: a.SkipTLSVerify},
		},
	}

	client := &Client{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
	}

	token, modernErr := a.authenticateModern(ctx, client)
	if modernErr == nil {
		client.SessionToken = token
		return client, nil
	}

	legacyErr := a.authenticateLegacy(ctx, client)
	if legacyErr == nil {
		client.LegacyAuth = true
		return client, nil
	}

	return nil, fmt.Errorf("pihole authentication failed: modern auth error: %v; legacy auth error: %w", modernErr, legacyErr)
}

func (a AuthProvider) Validate() error {
	if strings.TrimSpace(a.Hostname) == "" {
		return errors.New("hostname is required")
	}

	if strings.TrimSpace(a.Password) == "" {
		return errors.New("password is required")
	}

	if a.Port < 0 || a.Port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}

	return nil
}

func (a AuthProvider) baseURL() (*url.URL, error) {
	host := strings.TrimSpace(a.Hostname)
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}

	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("invalid hostname: %w", err)
	}

	if u.Scheme == "" {
		u.Scheme = "http"
	}

	if u.Host == "" {
		return nil, errors.New("invalid hostname: missing host")
	}

	if a.Port > 0 {
		u.Host = fmt.Sprintf("%s:%d", u.Hostname(), a.Port)
	} else if u.Port() == "" {
		if strings.EqualFold(u.Scheme, "https") {
			u.Host = fmt.Sprintf("%s:%d", u.Hostname(), 443)
		} else {
			u.Host = fmt.Sprintf("%s:%d", u.Hostname(), 80)
		}
	}

	u.Path = ""
	u.RawPath = ""

	return u, nil
}

func (a AuthProvider) authenticateModern(ctx context.Context, client *Client) (string, error) {
	endpoint := *client.BaseURL
	endpoint.Path = path.Join(endpoint.Path, "/api/auth")

	payload := authRequest{Password: a.Password}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to surface the actual message Pi-hole returned (e.g. "wrong password")
		var errBody map[string]any
		if jsonErr := json.Unmarshal(raw, &errBody); jsonErr == nil {
			// Pi-hole v6: error shape { "error": { "message": "..." } }
			if errObj, ok := errBody["error"].(map[string]any); ok {
				if msg, ok := errObj["message"].(string); ok && msg != "" {
					return "", fmt.Errorf("status %d from %s: %s", resp.StatusCode, endpoint.String(), msg)
				}
			}
			// Pi-hole v6: session shape { "session": { "message": "..." } }
			if session, ok := errBody["session"].(map[string]any); ok {
				if msg, ok := session["message"].(string); ok && msg != "" {
					return "", fmt.Errorf("status %d from %s: %s", resp.StatusCode, endpoint.String(), msg)
				}
			}
		}
		// Fallback: include raw body snippet so the user can see what the server returned
		snippet := strings.TrimSpace(string(raw))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		if snippet != "" {
			return "", fmt.Errorf("unexpected status code %d from %s: %s", resp.StatusCode, endpoint.String(), snippet)
		}
		return "", fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, endpoint.String())
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", fmt.Errorf("invalid auth response: %w", err)
	}

	// Pi-hole v6: token is nested inside the "session" object as "sid"
	if session, ok := decoded["session"].(map[string]any); ok {
		if sid, ok := session["sid"].(string); ok && strings.TrimSpace(sid) != "" {
			return sid, nil
		}
		// session object present but no sid — likely invalid credentials
		if valid, ok := session["valid"].(bool); ok && !valid {
			if msg, ok := session["message"].(string); ok && msg != "" {
				return "", fmt.Errorf("modern auth rejected: %s", msg)
			}
			return "", errors.New("modern auth rejected: invalid credentials")
		}
	}

	// Fallback: check top-level string fields for older API shapes
	for _, key := range []string{"sid", "token", "api_token"} {
		if value, ok := decoded[key].(string); ok && strings.TrimSpace(value) != "" {
			return value, nil
		}
	}

	return "", errors.New("modern auth succeeded but no token was returned")
}

func (a AuthProvider) authenticateLegacy(ctx context.Context, client *Client) error {
	endpoint := *client.BaseURL
	endpoint.Path = path.Join(endpoint.Path, "/admin/api.php")

	query := endpoint.Query()
	query.Set("auth", a.Password)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create legacy auth request: %w", err)
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read legacy auth response: %w", err)
	}

	body := strings.ToLower(strings.TrimSpace(string(raw)))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := body
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		if snippet != "" {
			return fmt.Errorf("unexpected status code %d from %s: %s", resp.StatusCode, endpoint.String(), snippet)
		}
		return fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, endpoint.String())
	}

	if strings.Contains(body, "\"status\":\"enabled\"") || strings.Contains(body, "\"status\":\"success\"") {
		return nil
	}

	if strings.Contains(body, "invalid") || strings.Contains(body, "unauthorized") {
		return errors.New("invalid password")
	}

	if body == "" {
		return errors.New("empty legacy auth response")
	}

	return nil
}
