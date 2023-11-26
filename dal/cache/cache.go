package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/redis/go-redis/v9"
	"time"
	"webx/dal/db"
	"webx/pkg/constants"
)

var once *UnifyCache

func Init() {
	client := redis.NewClient(&redis.Options{
		Addr:     constants.RedisAddr,
		Password: constants.RedisPassword,
		DB:       0,
	})
	once = NewUnifyCache(client)
}

type UnifyCache struct {
	client     redis.Cmdable
	expiration time.Duration
}

func NewUnifyCache(client redis.Cmdable) *UnifyCache {
	return &UnifyCache{
		client:     client,
		expiration: time.Minute * 15,
	}
}

func (c *UnifyCache) keyByUserId(id int64) string {
	return fmt.Sprintf("user:id:%d", id)
}

func (c *UnifyCache) keyByUserName(name string) string {
	return fmt.Sprintf("user:name:%s", name)
}

func (c *UnifyCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.client.Get(ctx, key).Bytes()
	return val, err
}

func (c *UnifyCache) Set(ctx context.Context, key string, val any) error {
	val, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, key, val, c.expiration).Err()
}

func GetUserById(ctx context.Context, id int64) (db.User, error) {
	key := once.keyByUserId(id)

	var user db.User
	data, err := once.Get(ctx, key)
	if err != nil {
		return user, err
	}
	err = json.Unmarshal(data, &user)
	return user, err
}

func SetUserById(ctx context.Context, user db.User) error {
	key := once.keyByUserId(user.Id)

	err := once.Set(ctx, key, user)
	if err != nil {
		return err
	}
	return nil
}

func GetUserByName(ctx context.Context, name string) (db.User, error) {
	key := once.keyByUserName(name)

	var user db.User
	data, err := once.Get(ctx, key)
	if err != nil {
		return user, err
	}
	err = json.Unmarshal(data, &user)
	return user, err
}

func SetUserByName(ctx context.Context, user db.User) error {
	key := once.keyByUserName(user.Username)

	err := once.Set(ctx, key, user)
	if err != nil {
		return err
	}
	return nil
}
