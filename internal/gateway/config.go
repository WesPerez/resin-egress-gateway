package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxRequestBody  = 8 << 20
	defaultMaxResponseBody = 8 << 20
)

type Config struct {
	ListenAddress         string
	AuthToken             string
	ResinBaseURL          *url.URL
	ResinProxyToken       string
	ResinPlatform         string
	StatePath             string
	MaxRequestBodyBytes   int64
	MaxResponseBodyBytes  int64
	MaxAttempts           int
	MaxInFlight           int
	MaxQueueWait          time.Duration
	ResponseHeaderTimeout time.Duration
	FirstByteTimeout      time.Duration
	ResponseBufferTimeout time.Duration
	MaxRetryAfter         time.Duration
	RouteStateTTL         time.Duration
	AllowHTTP             bool
	AllowPrivateTargets   bool
}

func LoadConfig() (Config, error) {
	baseURL, err := url.Parse(strings.TrimSpace(envOr("RESIN_BASE_URL", "http://proxy.internal:10834")))
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") {
		return Config{}, fmt.Errorf("RESIN_BASE_URL must be an absolute http(s) URL")
	}
	if baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return Config{}, fmt.Errorf("RESIN_BASE_URL must not contain query or fragment")
	}
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")

	authToken, err := readRequiredSecret("GATEWAY_TOKEN_FILE")
	if err != nil {
		return Config{}, err
	}
	proxyToken, err := readRequiredSecret("RESIN_PROXY_TOKEN_FILE")
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		ListenAddress:         envOr("LISTEN_ADDRESS", ":8080"),
		AuthToken:             authToken,
		ResinBaseURL:          baseURL,
		ResinProxyToken:       proxyToken,
		ResinPlatform:         envOr("RESIN_PLATFORM", "AppsGlobal"),
		StatePath:             envOr("STATE_PATH", "/data/state.json"),
		MaxRequestBodyBytes:   envInt64("MAX_REQUEST_BODY_BYTES", defaultMaxRequestBody),
		MaxResponseBodyBytes:  envInt64("MAX_RESPONSE_BODY_BYTES", defaultMaxResponseBody),
		MaxAttempts:           envInt("MAX_ATTEMPTS", 3),
		MaxInFlight:           envInt("MAX_IN_FLIGHT", 4),
		MaxQueueWait:          envDuration("MAX_QUEUE_WAIT", 30*time.Second),
		ResponseHeaderTimeout: envDuration("RESPONSE_HEADER_TIMEOUT", 30*time.Second),
		FirstByteTimeout:      envDuration("FIRST_BYTE_TIMEOUT", 30*time.Second),
		ResponseBufferTimeout: envDuration("RESPONSE_BUFFER_TIMEOUT", 2*time.Minute),
		MaxRetryAfter:         envDuration("MAX_RETRY_AFTER", 3*time.Second),
		RouteStateTTL:         envDuration("ROUTE_STATE_TTL", 30*24*time.Hour),
		AllowHTTP:             envBool("ALLOW_HTTP_TARGETS", false),
		AllowPrivateTargets:   envBool("ALLOW_PRIVATE_TARGETS", false),
	}
	if strings.TrimSpace(cfg.ResinPlatform) == "" || strings.ContainsAny(cfg.ResinPlatform, ".:|/\\@?#%~ \t\r\n") {
		return Config{}, fmt.Errorf("RESIN_PLATFORM is invalid")
	}
	if cfg.MaxAttempts < 1 || cfg.MaxAttempts > 5 {
		return Config{}, fmt.Errorf("MAX_ATTEMPTS must be between 1 and 5")
	}
	if cfg.MaxInFlight < 1 || cfg.MaxInFlight > 64 {
		return Config{}, fmt.Errorf("MAX_IN_FLIGHT must be between 1 and 64")
	}
	if cfg.MaxQueueWait < time.Second || cfg.MaxQueueWait > 5*time.Minute {
		return Config{}, fmt.Errorf("MAX_QUEUE_WAIT must be between 1s and 5m")
	}
	if cfg.MaxRequestBodyBytes < 1 || cfg.MaxRequestBodyBytes > 128<<20 {
		return Config{}, fmt.Errorf("MAX_REQUEST_BODY_BYTES must be between 1 and 128 MiB")
	}
	if cfg.MaxResponseBodyBytes < 1 || cfg.MaxResponseBodyBytes > 128<<20 {
		return Config{}, fmt.Errorf("MAX_RESPONSE_BODY_BYTES must be between 1 and 128 MiB")
	}
	if cfg.ResponseHeaderTimeout < time.Second || cfg.ResponseHeaderTimeout > 10*time.Minute {
		return Config{}, fmt.Errorf("RESPONSE_HEADER_TIMEOUT must be between 1s and 10m")
	}
	if cfg.FirstByteTimeout < time.Second || cfg.FirstByteTimeout > 10*time.Minute {
		return Config{}, fmt.Errorf("FIRST_BYTE_TIMEOUT must be between 1s and 10m")
	}
	if cfg.ResponseBufferTimeout < time.Second || cfg.ResponseBufferTimeout > 15*time.Minute {
		return Config{}, fmt.Errorf("RESPONSE_BUFFER_TIMEOUT must be between 1s and 15m")
	}
	if cfg.MaxRetryAfter < 0 || cfg.MaxRetryAfter > time.Minute {
		return Config{}, fmt.Errorf("MAX_RETRY_AFTER must be between 0 and 1m")
	}
	if cfg.RouteStateTTL < time.Hour {
		return Config{}, fmt.Errorf("ROUTE_STATE_TTL must be at least 1h")
	}
	return cfg, nil
}

func readRequiredSecret(envName string) (string, error) {
	path := strings.TrimSpace(os.Getenv(envName))
	if path == "" {
		return "", fmt.Errorf("%s is required", envName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", envName, err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s is empty", envName)
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("%s must contain one line", envName)
	}
	return value, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return fallback
	}
	return value
}

func envInt64(name string, fallback int64) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(name)), 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

var errStateVersion = errors.New("unsupported state version")
