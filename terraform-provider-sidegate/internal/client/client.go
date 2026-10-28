// SPDX-License-Identifier: MPL-2.0

// Package client talks to the sidegate management API (/api/v1).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrNotFound = errors.New("not found")

type Client struct {
	base      string
	token     string
	http      *http.Client
	userAgent string
}

func New(endpoint, token, version string) *Client {
	return &Client{
		base:      strings.TrimSuffix(endpoint, "/") + "/api/v1",
		token:     token,
		http:      &http.Client{Timeout: 30 * time.Second},
		userAgent: "terraform-provider-sidegate/" + version,
	}
}

type App struct {
	Name               string   `json:"name"`
	Subdomain          string   `json:"subdomain"`
	URL                string   `json:"url,omitempty"`
	Upstream           string   `json:"upstream"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	Icon               string   `json:"icon"`
	Category           string   `json:"category"`
	Public             bool     `json:"public"`
	Hidden             bool     `json:"hidden"`
	AllowedGroups      []string `json:"allowedGroups"`
	AllowedUsers       []string `json:"allowedUsers"`
	PublicPaths        []string `json:"publicPaths"`
	PassHostHeader     bool     `json:"passHostHeader"`
	HostHeader         string   `json:"hostHeader"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
	RequireMFA         bool     `json:"requireMFA"`
	MaxAuthAgeMinutes  int64    `json:"maxAuthAgeMinutes"`
}

type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// APIError is an error response from the API.
type APIError struct {
	Status  int
	Message string   `json:"error"`
	Details []string `json:"details"`
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("sidegate API returned %d: %s", e.Status, e.Message)
	if len(e.Details) > 0 {
		msg += "\n  - " + strings.Join(e.Details, "\n  - ")
	}
	return msg
}

func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

func (c *Client) GetApp(ctx context.Context, name string) (*App, error) {
	var out App
	return &out, c.do(ctx, http.MethodGet, "/apps/"+url.PathEscape(name), nil, &out)
}

func (c *Client) CreateApp(ctx context.Context, app App) (*App, error) {
	var out App
	return &out, c.do(ctx, http.MethodPost, "/apps", app, &out)
}

func (c *Client) UpdateApp(ctx context.Context, app App) (*App, error) {
	var out App
	return &out, c.do(ctx, http.MethodPut, "/apps/"+url.PathEscape(app.Name), app, &out)
}

func (c *Client) DeleteApp(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/apps/"+url.PathEscape(name), nil, nil)
}

func (c *Client) GetGroup(ctx context.Context, id string) (*Group, error) {
	var out Group
	return &out, c.do(ctx, http.MethodGet, "/groups/"+url.PathEscape(id), nil, &out)
}

// PutGroup creates or renames a group.
func (c *Client) PutGroup(ctx context.Context, g Group) (*Group, error) {
	var out Group
	return &out, c.do(ctx, http.MethodPut, "/groups/"+url.PathEscape(g.ID), Group{Name: g.Name}, &out)
}

func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/groups/"+url.PathEscape(id), nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		apiErr := &APIError{Status: resp.StatusCode}
		if json.Unmarshal(data, apiErr) != nil || apiErr.Message == "" {
			apiErr.Message = strings.TrimSpace(string(data))
			if apiErr.Message == "" {
				apiErr.Message = http.StatusText(resp.StatusCode)
			}
		}
		return apiErr
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response from %s %s: %w", method, path, err)
		}
	}
	return nil
}
