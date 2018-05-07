package googleIDVerifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"bytes"

	"golang.org/x/oauth2/jws"
)

var (
	nowFn = time.Now
)

func parseJWT(token string) (*jws.Header, *ClaimSet, error) {
	s := strings.Split(token, ".")
	if len(s) != 3 {
		return nil, nil, errors.New("Invalid token received")
	}
	decodedHeader, err := base64.RawURLEncoding.DecodeString(s[0])
	if err != nil {
		return nil, nil, err
	}
	header := &jws.Header{}
	err = json.NewDecoder(bytes.NewBuffer(decodedHeader)).Decode(header)
	if err != nil {
		return nil, nil, err
	}
	claimSet, err := Decode(token)
	if err != nil {
		return nil, nil, err
	}
	return header, claimSet, nil
}

// Decode returns ClaimSet
func Decode(token string) (*ClaimSet, error) {
	s := strings.Split(token, ".")
	if len(s) != 3 {
		return nil, ErrInvalidToken
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	c := &ClaimSet{}
	err = json.NewDecoder(bytes.NewBuffer(decoded)).Decode(c)
	return c, err
}
