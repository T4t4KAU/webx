package dal

import (
	"webx/dal/cache"
	"webx/dal/db"
)

func Init() {
	db.Init()
	cache.Init()
}
