package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultModel is the default judge model.
const DefaultModel = "claude-sonnet-5-5"

// Client calls the Anthropic Messages API with the standard library only.
type Client struct {
	APIKey    string
	BaseURL   string // default https://api.anthropic.com
	Model     string
	MaxTokens int
	HTTP      *http.Client
}

// NewClientFromEnv reads ANTHROPIC_API_KEY and ANTHROPIC_BASE_URL.
func NewClientFromEnv(model string) (*Client, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY is not set")
	}
	if model == "" {
		model = DefaultModel
	}
	return &Client{APIKey: key, BaseURL: os.Getenv("ANTHROPIC_BASE_URL"), Model: model}, nil
}

// Usage is token accounting for one call.
type Usage struct {
	InputTokens         int `json:"input_tokens"`
	OutputTokens        int `json:"output_tokens"`
	CacheReadTokens     int `json:"cache_read_input_tokens"`
	CacheCreationTokens int `json:"cache_creation_input_tokens"`
}

// Answer is the model's structured reply.
type Answer struct {
	DeclaredPurpose  string `json:"declared_purpose"`
	ObservedBehavior string `json:"observed_behavior"`
	Findings         []struct {
		Category string `json:"category"`
		Severity string `json:"severity"`
		File     string `json:"file"`
		Quote    string `json:"quote"`
		Reason   string `json:"reason"`
	} `json:"findings"`
	ManipulationAttempts []struct {
		File  string `json:"file"`
		Quote string `json:"quote"`
	} `json:"manipulation_attempts"`
}

type apiResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      Usage  `json:"usage"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// Ask sends one prompt and parses the structured answer. A refusal, a
// truncated answer or anything that does not parse is an error: the scan
// then ends in review, never in a clean result.
func (c *Client) Ask(ctx context.Context, p Prompt) (*Answer, Usage, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.anthropic.com"
	}
	maxTokens := c.MaxTokens
	if maxTokens == 0 {
		maxTokens = 8192
	}
	body := map[string]any{
		"model":      c.Model,
		"max_tokens": maxTokens,
		"system": []map[string]any{{
			"type": "text", "text": System, "cache_control": map[string]string{"type": "ephemeral"},
		}},
		"messages": []map[string]any{{
			"role": "user", "content": []map[string]string{{"type": "text", "text": p.User}},
		}},
		"output_config": map[string]any{"format": map[string]any{"type": "json_schema", "schema": Schema}},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, Usage{}, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Minute}
	}
	var resp apiResponse
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/messages", bytes.NewReader(buf))
		if err != nil {
			return nil, Usage{}, err
		}
		req.Header.Set("x-api-key", c.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("content-type", "application/json")
		res, err := hc.Do(req)
		if err != nil {
			return nil, Usage{}, fmt.Errorf("calling the Anthropic API: %w", err)
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		retryable := res.StatusCode == 429 || res.StatusCode == 529 || res.StatusCode >= 500
		if retryable && attempt < 3 {
			select {
			case <-time.After(time.Duration(2<<attempt) * time.Second):
				continue
			case <-ctx.Done():
				return nil, Usage{}, ctx.Err()
			}
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, Usage{}, fmt.Errorf("Anthropic API returned %d with an unreadable body", res.StatusCode)
		}
		if res.StatusCode != http.StatusOK {
			msg := res.Status
			if resp.Error != nil {
				msg = resp.Error.Type + ": " + resp.Error.Message
			}
			return nil, resp.Usage, fmt.Errorf("Anthropic API error %d: %s", res.StatusCode, msg)
		}
		break
	}
	switch resp.StopReason {
	case "refusal":
		return nil, resp.Usage, fmt.Errorf("the model declined to review this add-on")
	case "max_tokens":
		return nil, resp.Usage, fmt.Errorf("the model's answer was cut off at max_tokens")
	}
	var text strings.Builder
	for _, c := range resp.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}
	var ans Answer
	dec := json.NewDecoder(strings.NewReader(text.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ans); err != nil {
		return nil, resp.Usage, fmt.Errorf("the model's answer did not match the schema: %v", err)
	}
	return &ans, resp.Usage, nil
}
