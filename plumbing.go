package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
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

	//request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.authToken))
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", c.cx1UserAgent)
	}

	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}

	// add auth header
	err = c.refreshAccessToken()
	if err != nil {
		return &http.Request{}, fmt.Errorf("failed to get access token: %s", err)
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.auth.AccessToken))

	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	return request, nil
}

func (c *Cx1Client) sendTokenRequest(body io.Reader) (access_token string, err error) {
	tokenUrl := fmt.Sprintf("%v/auth/realms/%v/protocol/openid-connect/token", c.iamUrl, c.tenant)
	header := http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"},
		"User-Agent":   {c.cx1UserAgent},
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

	claims, err := parseJWT(access_token)
	if err != nil {
		return
	}
	c.SetClaims(claims)
	return
}

func (c *Cx1Client) refreshAccessToken() error {
	if c.auth.AccessToken == "" || c.auth.Expiry.Before(time.Now().Add(30*time.Second)) {
		c.logger.Tracef("Refreshing access token (%v) with expiry %v", ShortenGUID(c.auth.AccessToken), c.auth.Expiry)
		if c.auth.APIKey != "" {
			data := url.Values{}
			data.Set("grant_type", "refresh_token")
			data.Set("client_id", "ast-app")
			data.Set("refresh_token", c.auth.APIKey)

			access_token, err := c.sendTokenRequest(strings.NewReader(data.Encode()))
			if err != nil {
				return err
			}
			c.auth.AccessToken = access_token

			claims, err := parseJWT(c.auth.AccessToken)
			if err != nil {
				return fmt.Errorf("failed to parse API Key JWT: %v", err)
			}
			c.SetClaims(claims)
			c.auth.Expiry = c.claims.ExpiryTime
			c.logger.Tracef("New token (%v) has expiry %v", ShortenGUID(access_token), c.auth.Expiry)
		} else if c.auth.ClientID != "" && c.auth.ClientSecret != "" && c.iamUrl != "" && c.tenant != "" {
			data := url.Values{}
			data.Set("grant_type", "client_credentials")
			data.Set("client_id", c.auth.ClientID)
			data.Set("client_secret", c.auth.ClientSecret)

			access_token, err := c.sendTokenRequest(strings.NewReader(data.Encode()))
			if err != nil {
				return err
			}
			c.auth.AccessToken = access_token
			claims, err := parseJWT(c.auth.AccessToken)
			if err != nil {
				return fmt.Errorf("failed to parse API Key JWT: %v", err)
			}
			c.SetClaims(claims)
			c.auth.Expiry = c.claims.ExpiryTime
			c.logger.Tracef("New token (%v) has expiry %v", ShortenGUID(access_token), c.auth.Expiry)
		} else {
			return fmt.Errorf("invalid input: missing API key or ClientID + ClientSecret + IAMURL + TenantName")
		}
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
	c.logger.Tracef("Sending %v request to URL %v", method, url)
	request, err := c.createRequest(method, url, body, &header, nil)
	if err != nil {
		c.logger.Tracef("Unable to create request: %s", err)
		return nil, err
	}

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
	response, err := c.httpClient.Do(request)
	if err != nil || (response.StatusCode >= 500 && response.StatusCode < 600) {
		response, err = c.handleRetries(request, response, err)
	}

	if err != nil {
		if err.Error()[len(err.Error())-27:] == "net/http: use last response" {
			return response, nil
		} else {
			c.logger.Tracef("Failed HTTP request: '%s'", err)
			return response, err
		}
	}

	if response == nil {
		return nil, fmt.Errorf("nil response")
	}

	if response.StatusCode >= 400 {
		resBody, _ := io.ReadAll(response.Body)
		//c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		var msg map[string]interface{}
		err = json.Unmarshal(resBody, &msg)
		if err == nil {
			var str string
			if msg["message"] != nil {
				str = msg["message"].(string)
			} else if msg["error_description"] != nil {
				str = msg["error_description"].(string)
			} else if msg["error"] != nil {
				str = msg["error"].(string)
			} else if msg["errorMessage"] != nil {
				str = msg["errorMessage"].(string)
			} else {
				if len(str) > 20 {
					str = string(resBody)[:20]
				} else {
					str = string(resBody)
				}
			}
			return response, fmt.Errorf("HTTP %v: %v", response.Status, str)
		} else {
			str := string(resBody)
			if len(str) > 20 {
				str = str[:20]
			}
			return response, fmt.Errorf("HTTP %v: %s", response.Status, str)
		}
	}
	return response, nil
}

func (c *Cx1Client) handleRetries(request *http.Request, response *http.Response, err error) (*http.Response, error) {
	if err != nil && (strings.Contains(err.Error(), "tls: user canceled") && request.Method == http.MethodGet) { // tls: user canceled can be due to proxies
		c.logger.Warnf("Potentially benign error from HTTP connection: %s", err)
		return response, nil
	}

	delay := c.retryDelay
	attempt := 1
	for attempt <= c.maxRetries && ((response != nil && response.StatusCode >= 500 && response.StatusCode < 600) || isRetryableError(err)) {
		if response != nil {
			c.logger.Warnf("Response status %v: waiting %d seconds for retry attempt %d", response.Status, delay, attempt)
		} else {
			c.logger.Warnf("Request failed with %v: waiting %d seconds for retry attempt %d", err, delay, attempt)
		}

		attempt++

		// If there was a body, create a new reader for the retry from the buffered bytes.
		if request.GetBody != nil {
			body, err := request.GetBody()
			if err != nil {
				return response, fmt.Errorf("failed to get request body for retry: %w", err)
			}
			request.Body = body
		}

		jitter := time.Duration(rand.Intn(1000)) * time.Millisecond // Up to 1 second of jitter
		time.Sleep(time.Duration(delay)*time.Second + jitter)
		response, err = c.httpClient.Do(request)
		delay *= 2
	}

	return response, err
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
	cx1url := fmt.Sprintf("%v/api%v", c.baseUrl, url)
	return c.sendRequestInternal(method, cx1url, body, header)
}

func (c *Cx1Client) sendRequestRawCx1(method, url string, body io.Reader, header http.Header) (*http.Response, error) {
	cx1url := fmt.Sprintf("%v/api%v", c.baseUrl, url)
	return c.sendRequestRaw(method, cx1url, body, header)
}

func (c *Cx1Client) sendRequestIAM(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
	iamurl := fmt.Sprintf("%v%v/realms/%v%v", c.iamUrl, base, c.tenant, url)
	return c.sendRequestInternal(method, iamurl, body, header)
}

func (c *Cx1Client) sendRequestRawIAM(method, base, url string, body io.Reader, header http.Header) (*http.Response, error) {
	iamurl := fmt.Sprintf("%v%v/realms/%v%v", c.iamUrl, base, c.tenant, url)
	return c.sendRequestRaw(method, iamurl, body, header)
}

// not sure what to call this one? used for /console/ calls, not part of the /realms/ path
func (c *Cx1Client) sendRequestOther(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
	iamurl := fmt.Sprintf("%v%v/%v%v", c.iamUrl, base, c.tenant, url)
	return c.sendRequestInternal(method, iamurl, body, header)
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
	return c.cx1UserAgent
}
func (c *Cx1Client) SetUserAgent(ua string) {
	c.cx1UserAgent = ua
}

func (c *Cx1Client) GetRetries() (retries, delay int) {
	return c.maxRetries, c.retryDelay
}

func (c *Cx1Client) SetRetries(retries, delay int) {
	c.maxRetries = retries
	c.retryDelay = delay
}

// this function set the U-A to be the old one that was previously default in Cx1ClientGo
func (c *Cx1Client) SetUserAgentFirefox() {
	c.cx1UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"
}
