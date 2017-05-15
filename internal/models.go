package internal

type User struct {
	Username string                 `json:"username"`
	Password string                 `json:"password"`
	Data     map[string]interface{} `json:"data"`
}

type LoginInfo struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	RememberMe bool   `json:"rememberMe"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type ResetUserRequest struct {
	Username string `json:"username"`
}

type FinishResetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type ChangePasswordRequest struct {
	Username    string `json:"username"`
	NewPassword string `json:"newPassword"`
	OldPassword string `json:"oldPassword"`
}
