package db

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateUser(t *testing.T) {
	Init()
	user := &User{
		Username: "test",
		Password: "123456",
	}

	ctx := context.Background()
	id, err := CreateUser(ctx, user)
	assert.Nil(t, err)
	assert.Equal(t, id, user.Id)
}
