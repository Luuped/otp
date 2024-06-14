package otp

import (
	"crypto/hmac"
	"fmt"
	"net/url"
	"strings"
)

// BuildURI builds the OTP URI for provisioning.
func BuildURI(secret, name string, initialCount *int64, issuer, algorithm string, digits, period int, params map[string]string) (string, error) {
	otpType := "totp"
	if initialCount != nil {
		otpType = "hotp"
	}

	baseURI := "otpauth://%s/%s?%s"
	urlArgs := url.Values{}
	urlArgs.Add("secret", secret)

	if issuer != "" {
		urlArgs.Add("issuer", issuer)
		name = issuer + ":" + name
	}
	if initialCount != nil {
		urlArgs.Add("counter", fmt.Sprintf("%d", *initialCount))
	}
	if algorithm != "" && algorithm != "sha1" {
		urlArgs.Add("algorithm", strings.ToUpper(algorithm))
	}
	if digits != 6 {
		urlArgs.Add("digits", fmt.Sprintf("%d", digits))
	}
	if period != 30 {
		urlArgs.Add("period", fmt.Sprintf("%d", period))
	}

	for k, v := range params {
		urlArgs.Add(k, v)
	}

	return fmt.Sprintf(baseURI, otpType, url.PathEscape(name), urlArgs.Encode()), nil
}

// StringsEqual checks if two strings are equal.
func StringsEqual(s1, s2 string) bool {
	return hmac.Equal([]byte(s1), []byte(s2))
}
