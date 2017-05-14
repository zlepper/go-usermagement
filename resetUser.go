package usermanagement

import (
	"errors"
	"github.com/satori/go.uuid"
	"time"
)

type resetToken struct {
	Expiration time.Time
	Token      string
	Username   string
}

var (
	ErrInvalidResetToken error = errors.New("Invalid reset token")
)

func StartResetUser(resetUser Options, username string) error {
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

	err = resetUser.SendResetToken(token.Token, username)
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

func FinishUserReset(resetUser Options, token, password string) error {
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
