package googleIDVerifier

import (
	"strings"
	"testing"
	"time"
)

var (
	validTestToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjNmM2VmOWM3ODAzY2QwYjhkNzUyNDdlZTBkMzFmZGQ1YzJjZjM4MTIifQ.eyJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTQxNjAzMjAyNzUzOTM3NTU0MjQiLCJlbWFpbCI6InBsdXRvbmlvQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiWlpXdHQtVzRFV1h2VDZSVFhmRGFSUSIsImV4cCI6MTUyNTcyNTcxOSwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiaWF0IjoxNTI1NzIyMTE5fQ.I_kQV_5ElB-OFuVLT9vG2q_DvjX2tPy0WlnmUzK1l7rPBtBLtLipiS49KKT4tgRAGOLZn57qHXz_d3FRLaBD7_A2KShFkFd5rhZFH9Irti5rLHwJz4lqv3QTl-l9kTpEyQRuJWq48rtylyuZueZHyFqPHM1GB0lZfAAT3S9ECngfUhNY1u4J3v3f5RLhGw36xwn983b-pR9WHGf-pISLr5mnAY4zYrBuDk7KOnA8GW3SrN5pAUaK-4kP0QDRwXmTChiA5sKDrJAsT9tsp9z5sy0TqwQyrKsrrVaCc_DxRFfctn2Ff-2stG-Z85eQFBvxCO34QXdDsMPm5msx3764Sw"
	wrongSigToken  = validTestToken + "A"
)

type mockVerifier struct{}

// VerifyIDToken checks the validity of a given Google-issued OAuth2 token ID, using canned certs
func (v *mockVerifier) VerifyIDToken(idToken string, audience []string) error {
	certs, err := getTestCerts()
	if err != nil {
		return err
	}
	return VerifySignedJWTWithCerts(idToken, certs, audience, Issuers, MaxTokenLifetime)
}
func TestParseJWT(t *testing.T) {
	header, claimSet, _ := parseJWT(validTestToken)
	if len(header.KeyID) == 0 {
		t.Errorf("Invalid kid")
	}
	if len(claimSet.Email) == 0 {
		t.Errorf("Invalid Email")
	}
}

func TestVerifier(t *testing.T) {
	_, claimSet, _ := parseJWT(validTestToken)

	v := mockVerifier{}
	err := v.VerifyIDToken(wrongSigToken, []string{claimSet.Aud})
	if err != ErrWrongSignature {
		t.Error("Expect ErrWrongSignature")
	}
	err = v.VerifyIDToken(validTestToken, []string{claimSet.Aud})
	if err != nil && err != ErrTokenUsedTooLate {
		t.Error(err)
		t.Error("Expect ErrTokenUsedTooLate or actual valid token")
	}

	nowFn = func() time.Time {
		return time.Unix(claimSet.Exp, 0)
	}
	err = v.VerifyIDToken(validTestToken, []string{})
	if !strings.Contains(err.Error(), "Wrong aud:") {
		t.Error("Expect wrong aud error")
	}

	err = v.VerifyIDToken(validTestToken, []string{
		claimSet.Aud,
	})
	if err != nil {
		t.Error(err)
	}

	nowFn = time.Now
}
