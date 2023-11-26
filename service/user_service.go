package service

import (
	"context"
	"github.com/cloudwego/hertz/pkg/app"
	"golang.org/x/crypto/bcrypt"
	"webx/dal/db"
	"webx/pkg/errno"
)

type UserService struct {
	ctx context.Context
	c   *app.RequestContext
}

func NewUserService(ctx context.Context, c *app.RequestContext) *UserService {
	return &UserService{ctx: ctx, c: c}
}

type UserProfileReq struct {
	Id int64
}

type UserProfileResp struct {
	Email     string
	Signature string
}

func (svc *UserService) Profile(req *UserProfileReq) (resp *UserProfileResp, err error) {
	resp = new(UserProfileResp)

	user, err := db.QueryUserById(svc.ctx, req.Id)
	if err != nil {
		return
	}
	resp.Email = user.Email
	resp.Signature = user.Signature

	return
}

type UserRegisterReq struct {
	Username string
	Password string
}

type UserRegisterResp struct {
	Id    int64
	Token string
}

func (svc *UserService) Register(req *UserRegisterReq) (resp *UserRegisterResp, err error) {
	resp = new(UserRegisterResp)

	user, err := db.QueryUserByName(svc.ctx, req.Username)
	if err != nil {
		return resp, err
	}

	if user != (db.User{}) {
		return resp, errno.UserAlreadyExistErr
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), 5)
	if err != nil {
		return
	}

	uid, err := db.CreateUser(svc.ctx, &db.User{
		Username: req.Username,
		Password: string(hashed),
	})
	if err != nil {
		return
	}
	resp.Id = uid

	return
}

type UserEditReq struct {
	Id        int64
	Email     string
	Signature string
}

type UserEditResp struct{}

func (svc *UserService) Edit(req *UserEditReq) (resp *UserEditResp, err error) {
	resp = new(UserEditResp)

	err = db.EditUserProfile(svc.ctx, db.User{
		Id:        req.Id,
		Email:     req.Email,
		Signature: req.Signature,
	})
	if err != nil {
		return
	}
	return
}
