// Package otp provides TOTP (Time-based One-Time Password) functionality.
package otp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// IssuerName is the name shown in authenticator apps.
	IssuerName = "VC-Jump"
	// SecretSize is the size of the TOTP secret in bytes.
	SecretSize = 20
	// Period is the time step in seconds (standard is 30).
	Period = 30
	// Digits is the number of digits in the OTP code.
	Digits = 6
)

// Config holds OTP configuration.
type Config struct {
	// ForceEnabled requires all users to use OTP (admin override).
	ForceEnabled bool `json:"force_enabled" yaml:"force_enabled"`
	// Issuer name shown in authenticator apps.
	Issuer string `json:"issuer" yaml:"issuer"`
}

// DefaultConfig returns the default OTP configuration.
func DefaultConfig() Config {
	return Config{
		ForceEnabled: false,
		Issuer:       IssuerName,
	}
}

// GenerateSecret creates a new TOTP secret for a user.
func GenerateSecret(username string, issuer string) (*otp.Key, error) {
	if issuer == "" {
		issuer = IssuerName
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
		Period:      Period,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		SecretSize:  SecretSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	return key, nil
}

// GenerateQRCode generates a QR code image as base64 encoded PNG.
func GenerateQRCode(key *otp.Key, width, height int) (string, error) {
	if width <= 0 {
		width = 200
	}
	if height <= 0 {
		height = 200
	}

	img, err := key.Image(width, height)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code image: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", fmt.Errorf("failed to encode QR code: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// Validate checks if the provided OTP code is valid for the given secret.
func Validate(code string, secret string) bool {
	return totp.Validate(code, secret)
}

// ValidateWithTime checks if the OTP code is valid with a specific time.
// This is useful for testing.
func ValidateWithTime(code string, secret string, t time.Time) (bool, error) {
	return totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
		Period:    Period,
		Skew:      1, // Allow 1 period before/after for clock skew.
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// GenerateCode generates a TOTP code for the given secret at current time.
// This is mainly useful for testing.
func GenerateCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}

// UserOTPStatus represents the OTP status for a user.
type UserOTPStatus struct {
	Enabled  bool `json:"enabled"`  // OTP is enabled for this user.
	Verified bool `json:"verified"` // User has verified their OTP setup.
	Required bool `json:"required"` // OTP is required (forced by admin or user choice).
}

// ErrOTPRequired is returned when OTP verification is required but not provided.
var ErrOTPRequired = errors.New("OTP verification required")

// ErrOTPInvalid is returned when the OTP code is invalid.
var ErrOTPInvalid = errors.New("invalid OTP code")

// ErrOTPNotSetup is returned when OTP is required but not set up.
var ErrOTPNotSetup = errors.New("OTP is required but not set up for this user")
