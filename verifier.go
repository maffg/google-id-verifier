package googleIDVerifier

import (
	"fmt"
	"time"

	"golang.org/x/oauth2/jws"
)

var (
	// MaxTokenLifetime is one day
	MaxTokenLifetime = time.Second * 86400

	// ClockSkew - five minutes
	ClockSkew = time.Minute * 5

	// Issuers is the allowed oauth token issuers
	Issuers = []string{
		"accounts.google.com",
		"https://accounts.google.com",
	}
)

// TokenVerifier has a method to verify a Google-issued OAuth2 token ID
type TokenVerifier interface {
	// VerifyIDToken checks the validity of a given Google-issued OAuth2 token ID
	VerifyIDToken(idToken string, audience ...string) error
}

// CertsVerifier implements Verifier by fetching once in a while the Google certs and validating the ID tokens locally
type CertsVerifier struct {
	DefaultAudience []string
}

// VerifyIDToken checks the validity of a given Google-issued OAuth2 token ID
func (v *CertsVerifier) VerifyIDToken(idToken string, audience ...string) error {
	certs, err := getFederatedSignOnCerts()
	if err != nil {
		return err
	}
	if len(audience) == 0 {
		audience = v.DefaultAudience
	}
	return VerifySignedJWTWithCerts(idToken, certs, audience, Issuers, MaxTokenLifetime)
}

// VerifySignedJWTWithCerts is golang port of OAuth2Client.prototype.verifySignedJwtWithCerts
func VerifySignedJWTWithCerts(token string, certs *Certs, allowedAuds []string, issuers []string, maxExpiry time.Duration) error {
	header, claimSet, err := parseJWT(token)
	if err != nil {
		return err
	}
	key := certs.Keys[header.KeyID]
	if key == nil {
		return ErrPublicKeyNotFound
	}
	err = jws.Verify(token, key)
	if err != nil {
		return ErrWrongSignature
	}
	if claimSet.Iat < 1 {
		return ErrNoIssueTimeInToken
	}
	if claimSet.Exp < 1 {
		return ErrNoExpirationTimeInToken
	}
	now := nowFn()
	if claimSet.Exp > now.Unix()+int64(maxExpiry.Seconds()) {
		return ErrExpirationTimeTooFarInFuture
	}

	earliest := claimSet.Iat - int64(ClockSkew.Seconds())
	latest := claimSet.Exp + int64(ClockSkew.Seconds())

	if now.Unix() < earliest {
		return ErrTokenUsedTooEarly
	}

	if now.Unix() > latest {
		return ErrTokenUsedTooLate
	}

	found := false
	for _, issuer := range issuers {
		if issuer == claimSet.Iss {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("wrong issuer: %s", claimSet.Iss)
	}

	audFound := false
	for _, aud := range allowedAuds {
		if aud == claimSet.Aud {
			audFound = true
			break
		}
	}
	if !audFound {
		return fmt.Errorf("wrong aud: %s", claimSet.Aud)
	}

	return nil
}
