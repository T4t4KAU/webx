package main

import (
	"context"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"webx/dal"
	"webx/mw/auth"
	"webx/web"
)

func main() {
	dal.Init()
	auth.Init()

	router := server.New(
		server.WithHostPorts("0.0.0.0:8080"),
		server.WithHandleMethodNotAllowed(true),
	)

	userRouter := router.Group("/user")
	userRouter.POST("/register", web.UserRegister)
	userRouter.POST("/login", auth.UserLogin)
	userRouter.GET("/profile", auth.MiddlewareFunc(), web.UserProfile)
	userRouter.POST("/edit", auth.MiddlewareFunc(), web.UserEdit)

	router.NoRoute(func(ctx context.Context, c *app.RequestContext) {
		c.String(consts.StatusOK, "no route")
	})
	router.NoMethod(func(ctx context.Context, c *app.RequestContext) {
		c.String(consts.StatusOK, "no method")
	})

	router.Spin()
}
