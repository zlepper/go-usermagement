package usermanagement

import (
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	"github.com/zlepper/go-usermagement/internal"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var (
	ErrWrongUserOrPassword error = errors.New("Invalid User or password")
)

func Login(login Options, info internal.LoginInfo) (tokenString string, err error) {
	hashedPassword, err := login.GetPassword(info.Username)
	if err != nil {
		return "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(info.Password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return "", ErrWrongUserOrPassword
		} else {
			return "", err
		}
	}

	subject, err := login.GetSubjectData(info.Username)
	if err != nil {
		return "", err
	}

	loginDuration, err := login.GetLoginDuration(info.RememberMe)
	if err != nil {
		return "", err
	}

	issuer, err := login.GetIssuer()
	if err != nil {
		return "", err
	}

	claim, err := getStandardClaim(loginDuration, issuer, subject)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	signingKey, err := login.GetSigningSecret()
	if err != nil {
		return "", err
	}

	return token.SignedString(signingKey)

}

func getStandardClaim(expireAfter time.Duration, issuer string, subject interface{}) (claim *jwt.StandardClaims, err error) {
	sub, err := json.Marshal(subject)
	if err != nil {
		return nil, err
	}

	exp := time.Now().Add(expireAfter)

	return &jwt.StandardClaims{
		ExpiresAt: exp.Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    issuer,
		Id:        uuid.NewV4().String(),
		Subject:   string(sub),
	}, nil
}
