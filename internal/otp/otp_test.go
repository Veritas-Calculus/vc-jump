package otp

import (
	"testing"
	"time"
)

func TestGenerateSecret(t *testing.T) {
	key, err := GenerateSecret("testuser", "")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	if key.Secret() == "" {
		t.Error("Secret should not be empty")
	}

	if key.Issuer() != IssuerName {
		t.Errorf("Issuer = %s, want %s", key.Issuer(), IssuerName)
	}

	if key.AccountName() != "testuser" {
		t.Errorf("AccountName = %s, want testuser", key.AccountName())
	}
}

func TestGenerateSecretCustomIssuer(t *testing.T) {
	key, err := GenerateSecret("testuser", "CustomIssuer")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	if key.Issuer() != "CustomIssuer" {
		t.Errorf("Issuer = %s, want CustomIssuer", key.Issuer())
	}
}

func TestGenerateQRCode(t *testing.T) {
	key, err := GenerateSecret("testuser", "")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	qr, err := GenerateQRCode(key, 200, 200)
	if err != nil {
		t.Fatalf("GenerateQRCode failed: %v", err)
	}

	if len(qr) == 0 {
		t.Error("QR code should not be empty")
	}
}

func TestValidate(t *testing.T) {
	key, err := GenerateSecret("testuser", "")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	secret := key.Secret()

	// Generate a valid code.
	code, err := GenerateCode(secret)
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// Valid code should pass.
	if !Validate(code, secret) {
		t.Error("Valid code should pass validation")
	}

	// Invalid code should fail.
	if Validate("000000", secret) {
		t.Error("Invalid code should fail validation")
	}
}

func TestValidateWithTime(t *testing.T) {
	key, err := GenerateSecret("testuser", "")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	secret := key.Secret()
	now := time.Now()

	// Generate a valid code.
	code, err := GenerateCode(secret)
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// Should validate with current time.
	valid, err := ValidateWithTime(code, secret, now)
	if err != nil {
		t.Fatalf("ValidateWithTime failed: %v", err)
	}
	if !valid {
		t.Error("Code should be valid with current time")
	}

	// Should fail with time far in the future (beyond skew).
	valid, err = ValidateWithTime(code, secret, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("ValidateWithTime failed: %v", err)
	}
	if valid {
		t.Error("Code should be invalid with time 5 minutes in future")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ForceEnabled {
		t.Error("ForceEnabled should be false by default")
	}

	if cfg.Issuer != IssuerName {
		t.Errorf("Issuer = %s, want %s", cfg.Issuer, IssuerName)
	}
}
