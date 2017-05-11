package usermanagement

import (
	"errors"
	"github.com/satori/go.uuid"
	"time"
)

type ResetUser interface {
	// Should check if the User exists. If it does, return true, if not, return false.
	DoesUserExist(username string) (exists bool, err error)
	// Should get the time the reset token should be valid for
	GetResetTokenDuration() (duration time.Duration, err error)
	// Should save the given token and expiration time so it can be retrieved later on
	SaveToken(token string, expiration time.Time, username string) (err error)
	// Should send the reset token to the User somehow. This token should then be supplied for reset confirmation
	SendResetToken(token string) (err error)
	// Should fetch the expiration time for the given token
	GetTokenExpiration(token string) (expiration time.Time, err error)
	// Should validate that the given password matches any requirements for passwords
	ValidatePassword(password string) (err error)
	// Should set the users password to the given value
	SetUserPassword(username, password string) (err error)
	// Should ensure the deletion of the given token
	// At this point the users password has already been reset, so beware of returning errors here
	// unless something has gone completely wrong.
	DeleteToken(token string) (err error)
	// Should fetch the username related to the given token
	GetUsername(token string) (username string, err error)
}

type resetToken struct {
	Expiration time.Time
	Token      string
	Username   string
}

var (
	ErrInvalidResetToken error = errors.New("Invalid reset token")
)

func StartResetUser(resetUser ResetUser, username string) error {
	exists, err := resetUser.DoesUserExist(username)
	if err != nil {
		return err
	}

	// We can't leak that the User doesn't exists, so we'll just silently fail early
	if !exists {
		return nil
	}

	duration, err := resetUser.GetResetTokenDuration()
	if err != nil {
		return err
	}

	token := generateResetToken(duration, username)

	err = resetUser.SaveToken(token.Token, token.Expiration, token.Username)
	if err != nil {
		return err
	}

	err = resetUser.SendResetToken(token.Token)
	if err != nil {
		return err
	}

	return nil
}

func generateResetToken(duration time.Duration, username string) resetToken {
	return resetToken{
		Expiration: time.Now().Add(duration).UTC(),
		Token:      uuid.NewV4().String(),
		Username:   username,
	}
}

func FinishUserReset(resetUser ResetUser, token, password string) error {
	err := resetUser.ValidatePassword(password)
	if err != nil {
		return err
	}

	expiration, err := resetUser.GetTokenExpiration(token)
	if err != nil {
		return err
	}

	// Make sure the token hasn't yet expired
	if expiration.Before(time.Now().UTC()) {
		return ErrInvalidResetToken
	}

	username, err := resetUser.GetUsername(token)
	if err != nil {
		return err
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	err = resetUser.SetUserPassword(username, hash)
	if err != nil {
		return err
	}

	err = resetUser.DeleteToken(token)
	if err != nil {
		return err
	}

	return nil
}
