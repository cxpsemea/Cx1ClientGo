package Cx1ClientGo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// this file is for cx1clientgo internal functionality like sending HTTP requests

func (c *Cx1Client) createRequest(method, url string, body io.Reader, header *http.Header, cookies []*http.Cookie) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}

	for name, headers := range *header {
		for _, h := range headers {
			request.Header.Add(name, h)
		}
	}

	for name, headers := range c.config.HTTPHeaders {
		if request.Header.Get(name) == "" {
			for _, h := range headers {
				request.Header.Add(name, h)
			}
		}
	}

	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}

	// add auth header
	err = c.refreshAccessToken()
	if err != nil {
		return &http.Request{}, fmt.Errorf("failed to get access token: %s", err)
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.config.Auth.AccessToken))

	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	return request, nil
}

func (c *Cx1Client) sendTokenRequest(body io.Reader) (access_token string, err error) {
	tokenUrl := fmt.Sprintf("%v/auth/realms/%v/protocol/openid-connect/token", c.config.IAMUrl, c.config.Tenant)
	header := http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"},
	}

	for name, headers := range c.config.HTTPHeaders {
		for _, h := range headers {
			header.Add(name, h)
		}
	}

	request, err := http.NewRequest(http.MethodPost, tokenUrl, body)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %v", err)
	}
	request.Header = header

	response, err := c.handleHTTPResponse(request)
	if err != nil {
		return
	}
	var resBody []byte
	if response != nil && response.Body != nil {
		resBody, _ = io.ReadAll(response.Body)
		response.Body.Close()
	}

	var responseBody struct {
		AccessToken string `json:"access_token"`
	}

	err = json.Unmarshal(resBody, &responseBody)
	if err != nil {
		err = fmt.Errorf("failed to parse response body: %v", err)
		return
	}
	access_token = responseBody.AccessToken
	return
}

func (c *Cx1Client) refreshAccessToken() error {
	if c.config.Auth.AccessToken == "" || c.config.Auth.Expiry.Before(time.Now().Add(30*time.Second)) {
		c.config.Logger.Tracef("Refreshing access token (%v) with expiry %v", ShortenGUID(c.config.Auth.AccessToken), c.config.Auth.Expiry)

		data := url.Values{}
		if c.config.Auth.APIKey != "" {
			data.Set("grant_type", "refresh_token")
			data.Set("client_id", "ast-app")
			data.Set("refresh_token", c.config.Auth.APIKey)
		} else if c.config.Auth.ClientID != "" && c.config.Auth.ClientSecret != "" {
			data.Set("grant_type", "client_credentials")
			data.Set("client_id", c.config.Auth.ClientID)
			data.Set("client_secret", c.config.Auth.ClientSecret)
		} else {
			return fmt.Errorf("no valid authentication method available to refresh access token")
		}

		access_token, err := c.sendTokenRequest(strings.NewReader(data.Encode()))
		if err != nil {
			return err
		}
		c.config.Auth.AccessToken = access_token
		claims, err := parseJWT(c.config.Auth.AccessToken)
		if err != nil {
			return fmt.Errorf("failed to parse API Key JWT: %v", err)
		}
		c.claims = claims
		c.config.Auth.Expiry = c.claims.ExpiryTime
		c.config.Logger.Tracef("New token (%v) has expiry %v", ShortenGUID(access_token), c.config.Auth.Expiry)
	}
	return nil
}

func (c *Cx1Client) sendRequestInternal(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	response, err := c.sendRequestRaw(method, url, body, header)
	var resBody []byte
	if response != nil && response.Body != nil {
		resBody, _ = io.ReadAll(response.Body)
		response.Body.Close()
	}

	return resBody, err
}

func (c *Cx1Client) sendRequestRaw(method, url string, body io.Reader, header http.Header) (*http.Response, error) {
	return c.sendRequestRawContext(context.Background(), method, url, body, header)
}

// sendRequestRawContext is sendRequestRaw with a context: cancelling it aborts the request,
// including reading the body of a streaming response, and any retry waits.
func (c *Cx1Client) sendRequestRawContext(ctx context.Context, method, url string, body io.Reader, header http.Header) (*http.Response, error) {
	c.config.Logger.Tracef("Sending %v request to URL %v", method, url)
	request, err := c.createRequest(method, url, body, &header, nil)
	if err != nil {
		c.config.Logger.Tracef("Unable to create request: %s", err)
		return nil, err
	}
	request = request.WithContext(ctx)

	return c.handleHTTPResponse(request)
}

func (c *Cx1Client) handleHTTPResponse(request *http.Request) (*http.Response, error) {
	// If the request has a body, we need to buffer it so it can be read multiple times for retries.
	var bodyBytes []byte
	if request.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	response, err := c.config.HttpClient.Do(request)
	if err != nil || isRetryableStatus(response.StatusCode) {
		response, err = c.handleRetries(request, response, err)
	}

	if err != nil {
		if errors.Is(err, http.ErrUseLastResponse) || strings.HasSuffix(err.Error(), http.ErrUseLastResponse.Error()) {
			return response, nil
		} else {
			c.config.Logger.Tracef("Failed HTTP request: '%s'", err)
			return response, err
		}
	}

	if response == nil {
		return nil, fmt.Errorf("nil response")
	}

	if response.StatusCode == http.StatusUnauthorized {
		response, err = c.handleUnauthorized(request, response, bodyBytes)
		if err != nil {
			c.config.Logger.Tracef("Failed to recover from HTTP 401: %s", err)
			return response, err
		}
		if response == nil {
			return nil, fmt.Errorf("nil response")
		}
	}

	if response.StatusCode >= 400 {
		resBody, _ := io.ReadAll(response.Body)
		//c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		return response, fmt.Errorf("HTTP %v: %v", response.Status, httpErrorMessage(resBody))
	}
	return response, nil
}

// maxErrorBodyLength limits how much of an unparsed error response body is included in an error message.
const maxErrorBodyLength = 200

// httpErrorMessage extracts a human-readable message from an HTTP error response body.
// It never panics: if none of the known JSON fields contains a string (eg. the gateway returned
// {"error":{"code":403}}), it falls back to a truncated copy of the raw body.
func httpErrorMessage(resBody []byte) string {
	var msg map[string]interface{}
	if err := json.Unmarshal(resBody, &msg); err == nil {
		for _, key := range []string{"message", "error_description", "error", "errorMessage"} {
			if s, ok := msg[key].(string); ok && s != "" {
				return s
			}
		}
	}

	str := string(resBody)
	if len(str) > maxErrorBodyLength {
		str = str[:maxErrorBodyLength] + "..."
	}
	return str
}

// handleUnauthorized reacts to an HTTP 401 by forcing a fresh access token and retrying
// the request exactly once. This is needed because refreshAccessToken normally only
// refreshes when the client's own locally-tracked expiry says the token is about to
// expire - it has no way to know the server just rejected the token for some other
// reason (server-side revocation, clock skew, a concurrent refresh elsewhere, etc.).
// Without forcing a refresh here, a retry would just resend the identical stale token
// and get another 401, every time.
func (c *Cx1Client) handleUnauthorized(request *http.Request, response *http.Response, bodyBytes []byte) (*http.Response, error) {
	c.config.Auth.AccessToken = "" // force refreshAccessToken to actually fetch a new token instead of trusting the local expiry
	if err := c.refreshAccessToken(); err != nil {
		return response, fmt.Errorf("received HTTP 401 and failed to refresh access token: %w", err)
	}
	c.config.Logger.Tracef("Received HTTP 401, retrying once with a refreshed access token")

	if response.Body != nil {
		response.Body.Close()
	}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.config.Auth.AccessToken))
	if bodyBytes != nil {
		request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	return c.config.HttpClient.Do(request)
}

func (c *Cx1Client) handleRetries(request *http.Request, response *http.Response, err error) (*http.Response, error) {
	if err != nil && (strings.Contains(err.Error(), "tls: user canceled") && request.Method == http.MethodGet) { // tls: user canceled can be due to proxies
		c.config.Logger.Warnf("Potentially benign error from HTTP connection: %s", err)
		return response, nil
	}

	delay := *c.config.RetryDelay
	attempt := 1
	for shouldRetry(response, err) && attempt <= *c.config.MaxRetries {
		wait := time.Duration(delay) * time.Second
		if response != nil {
			// Honor Retry-After (typically sent with 429), capped so a bad value can't stall the caller
			if ra := parseRetryAfter(response.Header.Get("Retry-After")); ra > 0 {
				wait = min(ra, maxRetryAfter)
			}
			c.config.Logger.Warnf("Response status %v: waiting %v for retry attempt %d", response.Status, wait, attempt)
			// the previous response is discarded, release its connection
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		} else {
			c.config.Logger.Warnf("Request failed with %v: waiting %v for retry attempt %d", err, wait, attempt)
		}

		attempt++

		// If there was a body, create a new reader for the retry from the buffered bytes.
		if request.GetBody != nil {
			body, err := request.GetBody()
			if err != nil {
				return response, fmt.Errorf("failed to get request body for retry: %v", err)
			}
			request.Body = body
		}

		jitter := time.Duration(rand.Intn(1000)) * time.Millisecond // Up to 1 second of jitter
		select {
		case <-request.Context().Done():
			return nil, request.Context().Err()
		case <-time.After(wait + jitter):
		}
		response, err = c.config.HttpClient.Do(request)
		delay *= 2
	}

	return response, err
}

// maxRetryAfter is the longest wait honored from a Retry-After header.
const maxRetryAfter = 60 * time.Second

func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || (code >= 500 && code < 600)
}

func shouldRetry(response *http.Response, err error) bool {
	if err != nil {
		return isRetryableError(err)
	}
	return response != nil && isRetryableStatus(response.StatusCode)
}

// parseRetryAfter parses a Retry-After header (delay-seconds or HTTP-date). Returns 0 if absent or invalid.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func isRetryableError(err error) bool {
	// Check for network errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	// Check for DNS errors
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	// Check for connection refused errors
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	if strings.Contains(err.Error(), "tls: user canceled") {
		return true
	}

	return false
}

func (c *Cx1Client) sendRequest(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	cx1url := fmt.Sprintf("%v/api%v", c.config.Cx1Url, url)
	return c.sendRequestInternal(method, cx1url, body, header)
}

func (c *Cx1Client) sendRequestRawCx1(method, url string, body io.Reader, header http.Header) (*http.Response, error) {
	return c.sendRequestRawCx1Context(context.Background(), method, url, body, header)
}

func (c *Cx1Client) sendRequestRawCx1Context(ctx context.Context, method, url string, body io.Reader, header http.Header) (*http.Response, error) {
	cx1url := fmt.Sprintf("%v/api%v", c.config.Cx1Url, url)
	return c.sendRequestRawContext(ctx, method, cx1url, body, header)
}

func (c *Cx1Client) sendRequestIAM(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
	iamurl := fmt.Sprintf("%v%v/realms/%v%v", c.config.IAMUrl, base, c.config.Tenant, url)
	return c.sendRequestInternal(method, iamurl, body, header)
}

func (c *Cx1Client) sendRequestRawIAM(method, base, url string, body io.Reader, header http.Header) (*http.Response, error) {
	iamurl := fmt.Sprintf("%v%v/realms/%v%v", c.config.IAMUrl, base, c.config.Tenant, url)
	return c.sendRequestRaw(method, iamurl, body, header)
}

// not sure what to call this one? used for /console/ calls, not part of the /realms/ path
func (c *Cx1Client) sendRequestOther(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
	iamurl := fmt.Sprintf("%v%v/%v%v", c.config.IAMUrl, base, c.config.Tenant, url)
	return c.sendRequestInternal(method, iamurl, body, header)
}

func (c *Cx1Client) parseToken() {
	claims, err := parseJWT(c.config.Auth.AccessToken)
	if err != nil {
		c.config.Logger.Warnf("Failed to parse access token JWT: %v", err)
		return
	}

	c.claims = claims
	if claims.TenantID != "" {
		c.tenantID = claims.TenantID
	}

	c.config.ParseClaims(claims)

	c.Userinfo = Cx1TokenUserInfo{}
	c.Userinfo.UserID = claims.UserID
	c.Userinfo.UserName = claims.PreferredUsername
	if claims.ClientID != "" {
		c.Userinfo.ClientName = claims.ClientID
	}
}

func parseJWT(jwtToken string) (claims Cx1Claims, err error) {
	_, err = jwt.ParseWithClaims(jwtToken, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(nil), nil
	})

	if err != nil && !errors.Is(err, jwt.ErrTokenUnverifiable) && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		err = fmt.Errorf("failed to parse cx1 jwt token: %v", err)
		return
	}

	if claims.ISS != "" {
		var issURL *url.URL
		issURL, err = url.Parse(claims.ISS)
		if err != nil {
			err = fmt.Errorf("failed to parse iss claim as URL: %v", err)
			return
		}

		if claims.IAMURL == "" {
			claims.IAMURL = fmt.Sprintf("%v://%v", issURL.Scheme, issURL.Host)
		}

		parts := strings.Split(issURL.Path, "/")
		if claims.TenantName == "" {
			claims.TenantName = parts[len(parts)-1:][0]
		}
	}

	if claims.Expiry != 0 {
		claims.ExpiryTime = time.Unix(claims.Expiry, 0)
	}

	if len(claims.TenantID) > 36 {
		claims.TenantID = claims.TenantID[len(claims.TenantID)-36:]
	}

	return
}

func (c *Cx1Client) GetUserAgent() string {
	return c.config.HTTPHeaders.Get("User-Agent")
}
func (c *Cx1Client) SetUserAgent(ua string) {
	c.config.HTTPHeaders.Set("User-Agent", ua)
}

// this function sets the U-A to be the old one that was previously default in Cx1ClientGo
func (c *Cx1Client) SetUserAgentFirefox() {
	c.SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0")
}

func (c *Cx1Client) GetRetries() (retries, delay int) {
	return *c.config.MaxRetries, *c.config.RetryDelay
}

func (c *Cx1Client) SetRetries(retries, delay int) {
	c.config.MaxRetries = &retries
	c.config.RetryDelay = &delay
}

func (c *Cx1Client) GetHeaders() http.Header {
	return c.config.HTTPHeaders
}

func (c *Cx1Client) SetHeader(key, value string) {
	c.config.HTTPHeaders.Set(key, value)
}

func (c *Cx1Client) RemoveHeader(key string) {
	c.config.HTTPHeaders.Del(key)
}
