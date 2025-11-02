package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ReverseProxy struct {
	targetURL *url.URL
	client    *http.Client
}

func NewReverseProxy(targetAddr string) (*ReverseProxy, error) {
	targetURL, err := url.Parse(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: true,
		},
	}

	return &ReverseProxy{
		targetURL: targetURL,
		client:    client,
	}, nil
}

func (rp *ReverseProxy) ForwardRequest(r *http.Request) (*http.Response, error) {
	// Create new request to target
	req := r.Clone(r.Context())
	req.URL.Scheme = rp.targetURL.Scheme
	req.URL.Host = rp.targetURL.Host
	req.URL.Path = strings.TrimPrefix(r.URL.Path, "/")
	req.RequestURI = ""

	// Forward request to backend
	resp, err := rp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	return resp, nil
}

func (rp *ReverseProxy) CopyResponse(dst http.ResponseWriter, src *http.Response) error {
	// Copy headers
	for name, values := range src.Header {
		for _, value := range values {
			dst.Header().Add(name, value)
		}
	}

	// Copy status code
	dst.WriteHeader(src.StatusCode)

	// Copy body
	_, err := io.Copy(dst, src.Body)
	return err
}

func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}
