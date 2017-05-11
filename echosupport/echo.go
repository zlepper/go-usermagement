package echosupport

import (
	"github.com/labstack/echo"
	"github.com/zlepper/go-usermagement"
	"github.com/zlepper/go-usermagement/internal"
	"net/http"
)

func GetUserManagementRouter(g echo.Group, options usermanagement.Options) error {
	g.POST("/create", getCreateUserHandler(options))
	g.POST("/login", getLoginUserHandler(options))
	g.POST("/startreset", getStartResetUserHandler(options))
	g.POST("/finishreset", getFinishUserResetHandler(options))

	return nil
}

func getStartResetUserHandler(resetUser usermanagement.ResetUser) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request internal.ResetUserRequest
		err := c.Bind(&request)
		if err != nil {
			return err
		}

		err = usermanagement.StartResetUser(resetUser, request.Username)
		if err != nil {
			return err
		}
		return c.NoContent(http.StatusAccepted)
	}
}

func getLoginUserHandler(userLogin usermanagement.UserLogin) echo.HandlerFunc {
	return func(c echo.Context) error {
		var loginInfo internal.LoginInfo
		err := c.Bind(&loginInfo)
		if err != nil {
			return err
		}

		token, err := usermanagement.Login(userLogin, loginInfo)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, internal.LoginResponse{Token: token})
	}
}

func getCreateUserHandler(creation usermanagement.UserCreation) echo.HandlerFunc {
	return func(c echo.Context) error {
		var user internal.User
		err := c.Bind(&user)
		if err != nil {
			return err
		}

		err = usermanagement.CreateUser(creation, user)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusCreated)
	}
}

func getFinishUserResetHandler(resetUser usermanagement.ResetUser) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request internal.FinishResetRequest
		err := c.Bind(&request)
		if err != nil {
			return err
		}

		err = usermanagement.FinishUserReset(resetUser, request.Token, request.Password)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusOK)
	}
}
