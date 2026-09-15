package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	Base string
	HTTP *http.Client
}

func NewClient(base string) *Client {
	return &Client{Base: base, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Get(path string, q url.Values, out any) error {
	u := c.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	res, err := c.HTTP.Get(u)
	if err != nil {
		return unreachable(err)
	}
	return decode(res, out)
}

func (c *Client) Post(path string, body, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	res, err := c.HTTP.Post(c.Base+path, "application/json", &buf)
	if err != nil {
		return unreachable(err)
	}
	return decode(res, out)
}

// Stream opens the SSE endpoint and hands back the raw body for the caller to read.
func (c *Client) Stream(path string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", c.Base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, unreachable(err)
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, fmt.Errorf("event stream returned %d", res.StatusCode)
	}
	return res.Body, nil
}

func unreachable(err error) error {
	return fmt.Errorf("cannot reach ntcept: %w", err)
}

func decode(res *http.Response, out any) error {
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("control plane returned %d", res.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}
