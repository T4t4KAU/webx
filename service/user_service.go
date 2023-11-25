package service

import (
	"context"
	"github.com/cloudwego/hertz/pkg/app"
	"webx/dal/db"
)

type UserService struct {
	ctx context.Context
	c   *app.RequestContext
}

func NewUserService(ctx context.Context, c *app.RequestContext) *UserService {
	return &UserService{ctx: ctx, c: c}
}

type UserRegisterRequest struct {
	Username string
	Password string
}

type UserRegisterResponse struct {
	Id    int64
	Token string
}

func (svc *UserService) Register(req *UserRegisterRequest) (resp *UserRegisterResponse, err error) {
	resp = new(UserRegisterResponse)

	uid, err := db.CreateUser(svc.ctx, &db.User{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		return
	}
	resp.Id = uid

	return
}
