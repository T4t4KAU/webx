package web

import (
	"context"
	"errors"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
	"webx/mw/auth"
	"webx/pkg/errno"
	"webx/service"
)

func UserRegister(ctx context.Context, c *app.RequestContext) {
	var req service.UserRegisterReq

	if err := c.Bind(&req); err != nil {
		c.String(http.StatusBadRequest, "param error")
		return
	}

	_, err := service.NewUserService(ctx, c).Register(&req)
	if err != nil {
		if errors.Is(err, errno.UserAlreadyExistErr) {
			c.String(http.StatusOK, "user already exist")
		} else {
			c.String(http.StatusInternalServerError, "system error")
		}
		return
	}

	auth.UserLogin(ctx, c)
}

func UserProfile(ctx context.Context, c *app.RequestContext) {
	var req service.UserProfileReq

	if err := c.Bind(&req); err != nil {
		c.String(http.StatusBadRequest, "param error")
		return
	}

	resp, err := service.NewUserService(ctx, c).Profile(&req)
	if err != nil {
		c.String(http.StatusInternalServerError, "system error")
		return
	}

	c.JSON(http.StatusOK, resp)
}

func UserEdit(ctx context.Context, c *app.RequestContext) {
	type UserEditParam struct {
		Email     string
		Signature string
	}

	var param UserEditParam
	if err := c.Bind(&param); err != nil {
		c.String(http.StatusBadRequest, "param error")
		return
	}

	uid, _ := c.Get("current_user_id")
	_, err := service.NewUserService(ctx, c).Edit(&service.UserEditReq{
		Id:        uid.(int64),
		Email:     param.Email,
		Signature: param.Signature,
	})
	if err != nil {
		c.String(http.StatusInternalServerError, "system error")
		return
	}

	c.String(http.StatusOK, "edit ok")
}
