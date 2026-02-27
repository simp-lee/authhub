package authhub

import (
	"encoding/base64"
	"errors"
	"testing"
)

// --- GenerateState ---

func TestGenerateState_ReturnsNonEmptyString(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() error = %v", err)
	}
	if state == "" {
		t.Fatal("GenerateState() returned empty string")
	}
}

func TestGenerateState_Returns43CharString(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() error = %v", err)
	}
	// 32 bytes → base64url no padding → ceil(32*4/3) = 43 characters
	if len(state) != 43 {
		t.Errorf("GenerateState() len = %d; want 43", len(state))
	}
}

func TestGenerateState_IsValidBase64RawURL(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() error = %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		t.Fatalf("GenerateState() produced invalid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded length = %d; want 32", len(decoded))
	}
}

func TestGenerateState_ProducesUniqueValues(t *testing.T) {
	s1, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() first call error = %v", err)
	}
	s2, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() second call error = %v", err)
	}
	if s1 == s2 {
		t.Error("GenerateState() produced identical values on two calls")
	}
}

// --- ValidateState ---

func TestValidateState_MatchingStates(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() error = %v", err)
	}
	if err := ValidateState(state, state); err != nil {
		t.Errorf("ValidateState() with matching states returned error: %v", err)
	}
}

func TestValidateState_MismatchedStates(t *testing.T) {
	err := ValidateState("abc123", "xyz789")
	if err == nil {
		t.Fatal("ValidateState() with mismatched states returned nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %T", err)
	}
	if authErr.Kind != ErrKindInvalidCode {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindInvalidCode)
	}
	if authErr.Message != "state mismatch" {
		t.Errorf("Message = %q; want %q", authErr.Message, "state mismatch")
	}
	if !errors.Is(err, ErrInvalidCode) {
		t.Error("error should match ErrInvalidCode sentinel")
	}
}

func TestValidateState_EmptyExpected(t *testing.T) {
	err := ValidateState("", "some-state")
	if err == nil {
		t.Fatal("ValidateState() with empty expected returned nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %T", err)
	}
	if authErr.Kind != ErrKindInvalidCode {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindInvalidCode)
	}
	if authErr.Message != "state: expected and actual must not be empty" {
		t.Errorf("Message = %q; want %q", authErr.Message, "state: expected and actual must not be empty")
	}
}

func TestValidateState_EmptyActual(t *testing.T) {
	err := ValidateState("some-state", "")
	if err == nil {
		t.Fatal("ValidateState() with empty actual returned nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %T", err)
	}
	if authErr.Kind != ErrKindInvalidCode {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindInvalidCode)
	}
	if authErr.Message != "state: expected and actual must not be empty" {
		t.Errorf("Message = %q; want %q", authErr.Message, "state: expected and actual must not be empty")
	}
}

func TestValidateState_BothEmpty(t *testing.T) {
	err := ValidateState("", "")
	if err == nil {
		t.Fatal("ValidateState() with both empty returned nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %T", err)
	}
	if authErr.Kind != ErrKindInvalidCode {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindInvalidCode)
	}
}

func TestValidateState_DifferentLengthStrings(t *testing.T) {
	err := ValidateState("short", "a-much-longer-state-value")
	if err == nil {
		t.Fatal("ValidateState() with different length states returned nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %T", err)
	}
	if authErr.Kind != ErrKindInvalidCode {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindInvalidCode)
	}
	if authErr.Message != "state mismatch" {
		t.Errorf("Message = %q; want %q", authErr.Message, "state mismatch")
	}
}
