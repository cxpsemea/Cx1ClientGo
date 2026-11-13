package Cx1ClientGo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testLogger struct{}

func (testLogger) Tracef(string, ...interface{}) {}
func (testLogger) Debugf(string, ...interface{}) {}
func (testLogger) Infof(string, ...interface{})  {}
func (testLogger) Warnf(string, ...interface{})  {}
func (testLogger) Errorf(string, ...interface{}) {}
func (testLogger) Fatalf(string, ...interface{}) {}

// newTestClient builds a client pointed at the test server with a valid (unexpired) token so no auth requests are made.
func newTestClient(serverURL string, retries, delaySeconds int) *Cx1Client {
	return &Cx1Client{config: Cx1ClientConfiguration{
		HttpClient: http.DefaultClient,
		Auth:       Cx1ClientAuth{AccessToken: "test-token", Expiry: time.Now().Add(time.Hour)},
		Cx1Url:     serverURL,
		Logger:     testLogger{},
		Polling:    &ClientVars{},
		MaxRetries: &retries,
		RetryDelay: &delaySeconds,
	}}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"message string", `{"message":"bad thing"}`, "bad thing"},
		{"error_description string", `{"error_description":"invalid grant"}`, "invalid grant"},
		{"error string", `{"error":"forbidden"}`, "forbidden"},
		{"errorMessage string", `{"errorMessage":"oops"}`, "oops"},
		{"message precedence", `{"message":"a","error":"b"}`, "a"},
		{"error is object", `{"error":{"code":403}}`, `{"error":{"code":403}}`},
		{"message is number", `{"message":42}`, `{"message":42}`},
		{"message is array falls through to error", `{"message":["x"],"error":"fallback"}`, "fallback"},
		{"message is null", `{"message":null}`, `{"message":null}`},
		{"empty json object", `{}`, `{}`},
		{"not json", `<html>Forbidden</html>`, `<html>Forbidden</html>`},
		{"empty body", ``, ``},
		{"long body truncated", strings.Repeat("x", 500), strings.Repeat("x", maxErrorBodyLength) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpErrorMessage([]byte(tt.body)); got != tt.want {
				t.Errorf("httpErrorMessage(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

// A 4xx with a non-string error field used to panic.
func TestHandleHTTPResponse_ErrorBodyShapes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":403}}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 0, 0)
	_, err := c.sendRequest(http.MethodGet, "/x", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected HTTP 403 error, got %v", err)
	}
}

// A transport error whose message is shorter than 27 characters used to panic with a slice-bounds error.
func TestHandleHTTPResponse_ShortTransportError(t *testing.T) {
	c := newTestClient("http://x", 0, 0)
	c.config.HttpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("boom")
	})}
	if _, err := c.sendRequest(http.MethodGet, "/x", nil, nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestHandleHTTPResponse_UseLastResponse(t *testing.T) {
	c := newTestClient("http://x", 0, 0)
	c.config.HttpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, http.ErrUseLastResponse
	})}
	if _, err := c.sendRequestRaw(http.MethodGet, "http://x/y", nil, nil); err != nil {
		t.Fatalf("ErrUseLastResponse should be swallowed, got %v", err)
	}
}

func TestRetryOn429And5xx(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if atomic.AddInt32(&calls, 1) < 3 {
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(code)
					return
				}
				fmt.Fprint(w, "ok")
			}))
			defer srv.Close()

			c := newTestClient(srv.URL, 3, 1)
			start := time.Now()
			data, err := c.sendRequest(http.MethodGet, "/x", nil, nil)
			if err != nil || string(data) != "ok" {
				t.Fatalf("expected ok after retries, got %q, %v", data, err)
			}
			if n := atomic.LoadInt32(&calls); n != 3 {
				t.Errorf("expected 3 calls, got %d", n)
			}
			if time.Since(start) < 2*time.Second {
				t.Errorf("Retry-After: 1 should have caused ~2s of waiting, took %v", time.Since(start))
			}
		})
	}
}

func TestRetryGivesUp(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 1, 0)
	_, err := c.sendRequest(http.MethodGet, "/x", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("expected 429 error, got %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("expected 1 attempt + 1 retry = 2 calls, got %d", n)
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 3, 0)
	if _, err := c.sendRequest(http.MethodGet, "/x", nil, nil); err == nil {
		t.Fatal("expected error")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("expected 1 call, got %d", n)
	}
}

func TestRetryReplaysBody(t *testing.T) {
	var calls int32
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 100)
		n, _ := r.Body.Read(b)
		bodies = append(bodies, string(b[:n]))
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 2, 0)
	if _, err := c.sendRequest(http.MethodPost, "/x", strings.NewReader("payload"), nil); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || bodies[0] != "payload" || bodies[1] != "payload" {
		t.Errorf("body not replayed on retry: %q", bodies)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("7"); d != 7*time.Second {
		t.Errorf("seconds: got %v", d)
	}
	for _, v := range []string{"", "garbage", "-5"} {
		if d := parseRetryAfter(v); d != 0 {
			t.Errorf("%q: got %v, want 0", v, d)
		}
	}
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if d := parseRetryAfter(future); d <= 0 || d > 31*time.Second {
		t.Errorf("http-date: got %v", d)
	}
}

func TestRetryAbortsOnContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 3, 30) // would wait 30s without cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.sendRequestRawContext(ctx, http.MethodGet, srv.URL+"/x", nil, nil); err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("retry wait ignored context, took %v", time.Since(start))
	}
}
