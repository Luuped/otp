package otp

import (
	"crypto/sha1"
	"hash"
	"time"
)

// TOTP represents the Time-based One-Time Password structure.
type TOTP struct {
	*OTP
	Interval int64
}

// NewDefaultTOTP creates a new TOTP instance with default values.
func NewDefaultTOTP(secret string) (*TOTP, error) {
	return NewTOTP(secret, 6, sha1.New, "", "", 30)
}

// NewTOTP creates a new TOTP instance.
func NewTOTP(secret string, digits int, digest func() hash.Hash, name string, issuer string, interval int64) (*TOTP, error) {
	if digest == nil {
		digest = sha1.New
	}

	otp, err := NewOTP(secret, digits, digest, name, issuer)
	if err != nil {
		return nil, err
	}

	return &TOTP{
		OTP:      otp,
		Interval: interval,
	}, nil
}

// At generates the OTP for the given time and counter offset.
func (t *TOTP) At(forTime time.Time, counterOffset int64) (string, error) {
	return t.GenerateOTP(t.Timecode(forTime) + counterOffset)
}

// Now generates the current OTP.
func (t *TOTP) Now() (string, error) {
	return t.GenerateOTP(t.Timecode(time.Now()))
}

// Verify checks if the provided OTP is valid for the given time and window.
func (t *TOTP) Verify(otp string, forTime time.Time, validWindow int64) bool {
	if validWindow > 0 {
		for i := -validWindow; i <= validWindow; i++ {
			vAt, _ := t.At(forTime, i)
			if StringsEqual(otp, vAt) {
				return true
			}
		}
		return false
	}

	vAt, _ := t.At(forTime, 0)
	return StringsEqual(otp, vAt)
}

// Timecode calculates the timecode for a given time.
func (t *TOTP) Timecode(forTime time.Time) int64 {
	return forTime.Unix() / t.Interval
}
