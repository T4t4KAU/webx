package dal

import (
	"context"
	"github.com/T4t4KAU/webx/biz/dal/model"
	"github.com/T4t4KAU/webx/biz/dal/query"
	"golang.org/x/crypto/bcrypt"
)

func InsertUser(ctx context.Context, user model.User) error {
	return query.User.WithContext(ctx).Create(&user)
}

func QueryUserById(ctx context.Context, id int64) (model.User, error) {
	user, err := query.User.WithContext(ctx).Where(query.User.ID.Eq(id)).First()
	if err != nil {
		return model.User{}, err
	}
	return *user, nil
}

func QueryUserByName(ctx context.Context, name string) (model.User, error) {
	user, err := query.User.WithContext(ctx).Where(query.User.Username.Eq(name)).First()
	if err != nil {
		return model.User{}, err
	}
	return *user, nil
}

func VerifyUser(ctx context.Context, username string, password string) (int64, error) {
	user, err := QueryUserByName(ctx, username)
	if err != nil {
		return 0, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return 0, err
	}

	return user.ID, nil
}

func UpdateUser(ctx context.Context, user model.User) error {
	_, err := query.User.WithContext(ctx).
		Where(query.User.ID.Eq(user.ID)).Updates(user)
	return err
}
