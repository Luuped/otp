package otp

import (
	"crypto/hmac"
	"encoding/base32"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// OTP represents the base structure for OTP generation and verification.
type OTP struct {
	Secret string
	Digits int
	Digest func() hash.Hash
	Name   string
	Issuer string
}

// NewDefaultOTP creates a new OTP instance with default values.
func NewDefaultOTP(secret string) (*OTP, error) {
	return NewOTP(secret, 6, nil, "", "")
}

// NewOTP creates a new OTP instance.
func NewOTP(secret string, digits int, digest func() hash.Hash, name string, issuer string) (*OTP, error) {
	if digits > 10 {
		return nil, errors.New("digits must be no greater than 10")
	}

	if name == "" {
		name = "Secret"
	}

	return &OTP{
		Secret: secret,
		Digits: digits,
		Digest: digest,
		Name:   name,
		Issuer: issuer,
	}, nil
}

// GenerateOTP generates an OTP value for a given input.
func (o *OTP) GenerateOTP(input int64) (string, error) {
	if input < 0 {
		return "", errors.New("input must be a positive integer")
	}

	h := hmac.New(o.Digest, o.byteSecret())
	h.Write(o.intToBytestring(input))
	hmacHash := h.Sum(nil)

	offset := hmacHash[len(hmacHash)-1] & 0xF
	code := (int(hmacHash[offset]&0x7F) << 24) |
		(int(hmacHash[offset+1]&0xFF) << 16) |
		(int(hmacHash[offset+2]&0xFF) << 8) |
		(int(hmacHash[offset+3] & 0xFF))

	strCode := fmt.Sprintf(fmt.Sprintf("%%0%dd", o.Digits), code%pow(10, o.Digits))
	return strCode, nil
}

func (o *OTP) byteSecret() []byte {
	secret := o.Secret
	missingPadding := len(secret) % 8
	if missingPadding != 0 {
		secret += strings.Repeat("=", 8-missingPadding)
	}
	bytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil
	}
	return bytes
}

func (o *OTP) intToBytestring(input int64) []byte {
	var result []byte
	for input != 0 {
		result = append(result, byte(input&0xFF))
		input >>= 8
	}
	for len(result) < 8 {
		result = append(result, 0)
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

func pow(a, b int) int {
	result := 1
	for b != 0 {
		if (b & 1) != 0 {
			result *= a
		}
		a *= a
		b >>= 1
	}
	return result
}
