// Code generated by hertz generator. DO NOT EDIT.

package article

import (
	article "github.com/T4t4KAU/webx/biz/handler/article"
	"github.com/cloudwego/hertz/pkg/app/server"
)

/*
 This file will register all the routes of the services in the master idl.
 And it will update automatically when you use the "update" command for the idl.
 So don't modify the contents of the file, or your code will be deleted when it is updated.
*/

// Register register routes based on the IDL 'api.${HTTP Method}' annotation.
func Register(r *server.Hertz) {

	root := r.Group("/", rootMw()...)
	{
		_article := root.Group("/article", _articleMw()...)
		_article.POST("/create", append(_createMw(), article.Create)...)
		_article.POST("/delete", append(_deleteMw(), article.Delete)...)
		_article.POST("/edit", append(_editMw(), article.Edit)...)
		_article.GET("/hide", append(_hideMw(), article.Hide)...)
		_article.GET("/info", append(_getinfoMw(), article.GetInfo)...)
		_article.POST("/publish", append(_publishMw(), article.Publish)...)
	}
}
