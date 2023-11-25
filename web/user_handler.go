package web

import (
	"context"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
	"webx/mw/auth"
	"webx/service"
)

func UserRegister(ctx context.Context, c *app.RequestContext) {
	var req service.UserRegisterRequest

	if err := c.Bind(&req); err != nil {
		c.String(http.StatusInternalServerError, "system error")
		return
	}

	_, err := service.NewUserService(ctx, c).Register(&req)
	if err != nil {
		c.String(http.StatusInternalServerError, "system error")
		return
	}

	auth.UserLogin(ctx, c)

	c.String(http.StatusOK, "register ok")
}
