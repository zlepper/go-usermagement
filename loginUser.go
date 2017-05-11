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

type UserLogin interface {
	// Should get the password for the given User, or an error if something goes wrong
	// If the User is not found, then an empty password and no error should be returned
	GetPassword(username string) (password string, err error)
	// Should get all data that should be put in the resulting jwt, as the subject
	// This could include stuff like the users actual name or any rights they have
	// The returned interface should be able to be put through the standard json marshaller
	GetSubjectData(username string) (data interface{}, err error)
	// Should return a key to sign the jwt token with
	GetSigningSecret() (signingKey string, err error)
	// Should return the time the login should stay valid
	// rememberMe is set to true if the User would like to be remember for a longer duration
	GetLoginDuration(rememberMe bool) (duration time.Duration, err error)
	// Get the issuer of the login. Would normally be the application name,
	// or a link to the running application
	GetIssuer() (issuer string, err error)
}

var (
	ErrWrongUserOrPassword error = errors.New("Invalid User or password")
)

func Login(login UserLogin, info internal.LoginInfo) (tokenString string, err error) {
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
		return nil, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	signingKey, err := login.GetSigningSecret()
	if err != nil {
		return nil, err
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
