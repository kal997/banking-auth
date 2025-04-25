package domain

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/kal997/banking-lib/errs"
	"github.com/kal997/banking-lib/logger"
)

type AuthToken struct {
	token *jwt.Token
}

// factory method
func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token}

}

func (a AuthToken) NewAccessToken() (string, *errs.AppError) {

	signedStr, err := a.token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("Failed while signing access token: " + err.Error())
		return "", errs.NewUnexpectedError("cannot generate access token")
	}
	return signedStr, nil

}
