package usermanagement

import "time"

type Options interface {
	// Should validate if the username is valid (e.g. validate that it's an email if
	// that is the kind of usernames being used)
	ValidateUser(username, password string, data map[string]interface{}) error
	// Should save the User to some sort of persistence layer (A database would be a good idea)
	CreateUser(username, password string, data map[string]interface{}) error
	// Should get the password for the given User, or an error if something goes wrong
	// If the User is not found, then an empty password and no error should be returned
	GetPassword(username string) (password string, err error)
	// Should get all data that should be put in the resulting jwt, as the subject
	// This could include stuff like the users actual name or any rights they have
	// The returned interface should be able to be put through the standard json marshaller
	GetSubjectData(username string) (data interface{}, err error)
	// Should return a key to sign the jwt token with
	GetSigningSecret() (signingKey []byte, err error)
	// Should return the time the login should stay valid
	// rememberMe is set to true if the User would like to be remember for a longer duration
	GetLoginDuration(rememberMe bool) (duration time.Duration, err error)
	// Get the issuer of the login. Would normally be the application name,
	// or a link to the running application
	GetIssuer() (issuer string, err error)
	// Should check if the User exists. If it does, return true, if not, return false.
	DoesUserExist(username string) (exists bool, err error)
	// Should get the time the reset token should be valid for
	GetResetTokenDuration() (duration time.Duration, err error)
	// Should save the given token and expiration time so it can be retrieved later on
	SaveToken(token string, expiration time.Time, username string) (err error)
	// Should send the reset token to the User somehow. This token should then be supplied for reset confirmation
	SendResetToken(token, username string) (err error)
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
