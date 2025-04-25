package domain

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"
const ACCESS_TOKEN_DURATION = time.Hour

type AccessTokenClaims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	jwt.StandardClaims
}

func (c AccessTokenClaims) IsUserRole() bool {
	return c.Role == "user"
}

func (c AccessTokenClaims) IsValidAccountId(accountId string) bool {

	accountResult := false

	if accountId != "" {
		for _, acc := range c.Accounts {
			if acc == accountId {
				accountResult = true
				break
			}
		}
	}
	return accountResult
}
func (c AccessTokenClaims) IsRequestedVerifiedWithTokenClaims(urlParams map[string]string) bool {
	if c.CustomerId != urlParams["customer_id"] {
		return false
	}

	if urlParams["routeName"] == "NewTransaction" {
		if !c.IsValidAccountId(urlParams["account_id"]) {
			return false
		}
	}
	return true
}
