package googleIDVerifier

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

type Certs struct {
	Keys   map[string]*rsa.PublicKey
	Expiry time.Time
}

var (
	cachedCerts *Certs

	// Google Sign on certificates.
	googleOAuth2FederatedSignOnCertsURL = "https://www.googleapis.com/oauth2/v3/certs"
)

type key struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"Kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type response struct {
	Keys []*key `json:"keys"`
}

func getFederatedSignOnCerts() (*Certs, error) {
	if cachedCerts != nil {
		if time.Now().Before(cachedCerts.Expiry) {
			return cachedCerts, nil
		}
	}

	res, cacheAge, err := fetchFederatedSignOnCerts()
	if err != nil {
		return nil, err
	}

	parsedCerts, err := parseCerts(res, cacheAge)
	if err != nil {
		return nil, err
	}

	// cache certs
	cachedCerts = parsedCerts

	return parsedCerts, nil
}

func fetchFederatedSignOnCerts() (*response, int64, error) {
	resp, err := http.Get(googleOAuth2FederatedSignOnCertsURL)
	if err != nil {
		return nil, 0, err
	}
	cacheControl := resp.Header.Get("cache-control")
	cacheAge := int64(7200) // Set default cacheAge to 2 hours
	if len(cacheControl) > 0 {
		re := regexp.MustCompile("max-age=([0-9]*)")
		match := re.FindAllStringSubmatch(cacheControl, -1)
		if len(match) > 0 {
			if len(match[0]) == 2 {
				maxAge := match[0][1]
				maxAgeInt, err := strconv.ParseInt(maxAge, 10, 64)
				if err != nil {
					return nil, 0, err
				}
				cacheAge = maxAgeInt
			}
		}
	}

	res := &response{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, 0, err
	}

	return res, cacheAge, nil
}

func parseCerts(res *response, cacheAge int64) (*Certs, error) {
	keys := map[string]*rsa.PublicKey{}
	for _, key := range res.Keys {
		if key.Use == "sig" && key.Kty == "RSA" {
			n, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, err
			}
			e, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, err
			}
			ei := big.NewInt(0).SetBytes(e).Int64()
			keys[key.Kid] = &rsa.PublicKey{
				N: big.NewInt(0).SetBytes(n),
				E: int(ei),
			}
		}
	}
	return &Certs{
		Keys:   keys,
		Expiry: time.Now().Add(time.Second * time.Duration(cacheAge)),
	}, nil
}
