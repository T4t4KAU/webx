# 业务后端开发与实践

毕业在即，本人现已投身于业务后端的研发，回顾一年来在此领域的学习和实践，写下这篇文章，既是分享自己的一点点收获，也是纪念这一段快乐的时光。因此这既是一篇技术创作，也是一篇属于个人的回忆录，希望以这种方式总结过去的成长，激励自己在未来更加努力。

本文的特点：

1. 使用语言：Go
2. 使用的框架：Hertz、Kitex、Gorm
3. 附带完整的代码实现

仓库地址：https://github.com/T4t4KAU/webx

## 快速起步

Hertz是字节跳动研发的HTTP框架，具有高易用、高性能和高扩展性等特点

快速入门：https://www.cloudwego.io/zh/docs/hertz/getting-started/

下面会基于Hertz写一个简单的用户注册和登录接口，登录和注册是非常常见的功能。在注册过程中，用户输入用户名、密码以及其他必要的信息，然后发起注册请求。一旦注册成功，用户的账号信息将被添加到系统中。而在登录过程中，用户使用之前注册时所使用的用户名和密码，再加上其他验证信息，即可成功登录。

下面将确定用户信息的存储方式和表结构，包括用户名、密码、用户信息等，考虑密码的加密存储和验证机制。

### 数据库设计

安装Gorm:

```powershell
go get -u gorm.io/gorm
```

可以使用Docker Compose快速部署一个MySQL，在工作目录编写 `docker-compose.yaml` 文件:

```yaml
version: '3.0'
services:
  mysql:
    image: mysql:latest
    restart: always
    environment:
      - MYSQL_DATABASE=webx
      - MYSQL_USER=test
      - MYSQL_PASSWORD=123456
      - MYSQL_RANDOM_ROOT_PASSWORD="yes"
    volumes:
      - ./script/mysql/:/docker-entrypoint-initdb.d/
    ports:
      - "13306:3306"
```

执行以下命令即可启动完成：

```powershell
docker-compose up -d
```

使用Gorm初始化数据库连接：

```go
var dao *gorm.DB

func Init() {
	var err error
	dao, err = gorm.Open(mysql.Open(consts.MySQLDSN),
		&gorm.Config{
			PrepareStmt:            true,
			SkipDefaultTransaction: true,
		})

	if err != nil {
		panic(err)
	}

	if err = dao.Use(gormopentracing.New()); err != nil {
		panic(err)
	}

	err = dao.AutoMigrate(&User{})
	if err != nil {
		panic(err)
	}
}

```

上述代码中，使用 `gorm.Open` 打开一个MySQL数据库连接，该函数需要接收一个DSN，大概是如下形式：

```
[username[:password]@][protocol[(address)]]/dbname[?param1=value1&param2=value2...]
```

例如，要连接本地数据库：

```
username:password@tcp(127.0.0.1:3306)/dbname
```

同时启用语句预编译来提高查询性能和安全性。 `dao.Use(gormopentracing.New())` 注册一个Gorm的插件，用于在GORM操作中添加OpenTracing的跟踪功能。

定义User结构：

```go
type User struct {
	Id       int64  `json:"id"`
	UserName string `json:"username"`
	PassWord string `json:"password"`
	Email    string `json:"email"`
}

func (User) TableName() string {
	return "tb_user"
}
```

为User定义了一个方法 TableName，将User模型对象映射到指定的表名

创建用户：

```go
func CreateUser(ctx context.Context, user *User) (int64, error) {
	err := dao.WithContext(ctx).Create(user).Error
	if err != nil {
		return 0, err
	}
	return user.Id, nil
}
```

这个方法很简单，如果执行成功会在数据库中添加该用户数据，并返回用户的ID

接着写一段简单的单元测试函数来检验函数是否达到了预期：

```go
func TestCreateUser(t *testing.T) {
	Init()
	user := &User{
		Username: "test",
		Password: "123456",
	}

	ctx := context.Background()
	id, err := CreateUser(ctx,user)
	assert.Nil(t, err)
	assert.Equal(t, id, user.Id)
}
```

### 业务设计

下面实现用户注册的业务逻辑

```go
package service

type UserService struct {
	ctx context.Context
	c   *app.RequestContext
}

// 创建用户服务
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

// 注册用户
func (svc *UserService) Register(req *UserRegisterRequest) (resp *UserRegisterResponse, err error) {
	resp = new(UserRegisterResponse)
	
	uid, err := db.CreateUser(&db.User{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		return
	}
	resp.Id = uid
    
	return
}
```

这里只要读取请求，然后调用上述写好的数据库接口即可

### 请求处理

编写如下函数，形式上要符合 `app.HandlerFunc`

```go
func UserRegister(ctx context.Context, c *app.RequestContext) {
	var req service.UserRegisterRequest

	if err := c.Bind(&req); err != nil {
		c.String(http.StatusInternalServerError, "system error")
		return
	}
	
    // 创建 User 服务
	_, err := service.NewUserService(ctx, c).Register(&req)
	if err != nil {
		c.String(http.StatusInternalServerError, "system error")
		return
	}
	c.String(http.StatusOK, "register ok")
}
```

注册路由：

```go
func main() {
	dal.Init() // 初始化数据层
	router := server.New(
		server.WithHostPorts("0.0.0.0:8080"),
		server.WithHandleMethodNotAllowed(true),
	)

	router.POST("/user/register", web.UserRegister) // 注册路由
	router.NoRoute(func(ctx context.Context, c *app.RequestContext) {
		c.String(consts.StatusOK, "no route")
	})
	router.NoMethod(func(ctx context.Context, c *app.RequestContext) {
		c.String(consts.StatusOK, "no method")
	})

	router.Spin()
}
```

注册路由的作用就是将特定的URL路径与处理函数关联起来，以便在接收到对应路径的HTTP请求时执行相应的处理逻辑。

到这里就可以进行测试了，用curl发送一条POST请求：

```shell
curl --location --request POST 'http://127.0.0.1:8080/user/register' \
--header 'User-Agent: Apifox/1.0.0 (https://apifox.com)' \
--header 'Content-Type: application/json' \
--data-raw '{
    "username":"test",
    "password":"123456"
}'
```

### 用户鉴权

下面就要实现登录功能了，这里牵涉到一个登录鉴权问题，也就是如何验证用户身份，确保只有经过身份验证的用户可以访问受限资源或执行特定操作。有两种很常见的实现，一个是session一个是jwt，这里使用jwt。

使用JWT进行鉴权一般流程如下：

1. 用户登录：用户提供凭证进行登录，服务器验证凭证成功后，生成JWT。
2. 令牌传递：服务器将JWT返回给客户端，客户端将其保存在本地。
3. 请求授权：客户端在后续的请求中，将JWT作为Bearer令牌放在请求的`Authorization`头部中。
4. 服务器验证：服务器在接收到请求时，从`Authorization`头部中提取JWT，并进行验证。验证包括检查令牌的有效性、签名是否正确以及令牌是否过期等。
5. 授权访问：如果JWT验证通过，服务器可以使用令牌中的信息来授权用户访问特定的资源或执行特定的操作。

下面完善jwt鉴权功能，首先在数据层补充一个函数：

```go
func VerifyUser(username string, password string) (int64, error) {
	var user User
	err := dao.Where("username = ? AND password = ?", username, password).Find(&user).Error
	if err != nil {
		return 0, err
	}
	if user.Id == 0 {
		return user.Id, errno.PasswordIsNotVerified
	}
	return user.Id, nil
}
```

该函数接收用户名和密码作为参数，用于校验用户名和密码的正确性

在Hertz中可以在Middleware中初始化JWT组件：

```go
var (
	once *jwt.HertzJWTMiddleware
)

func Init() {
	// 创建jwt middleware
	once, _ = jwt.New(&jwt.HertzJWTMiddleware{
		Key:     []byte(constants.SecretKey),
		Timeout: time.Hour * 24,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(int64); ok {
				return jwt.MapClaims{
					constants.IdentityKey: v,
				}
			}
			return jwt.MapClaims{}
		},
		HTTPStatusMessageFunc: func(e error, ctx context.Context, c *app.RequestContext) string {
			var errNo errno.ErrNo
			switch {
			case errors.As(e, &errNo):
				return e.(errno.ErrNo).ErrMsg
			default:
				return e.Error()
			}
		},
		LoginResponse: func(ctx context.Context, c *app.RequestContext, code int, token string, expire time.Time) {
			c.JSON(consts.StatusOK, map[string]interface{}{
				"status_code": errno.SuccessCode,
				"status_msg":  errno.SuccessMsg,
				"token":       token,
			})
		},
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			c.JSON(code, map[string]interface{}{
				"status_code": errno.AuthorizationFailedErrCode,
				"status_msg":  message,
			})
		},
		Authenticator: func(ctx context.Context, c *app.RequestContext) (interface{}, error) {
			type LoginParam struct {
				Username string
				Password string
			}

			var param LoginParam
			if err := c.BindAndValidate(&param); err != nil {
				return nil, err
			}
			uid, err := db.VerifyUser(param.Username, param.Password)
			if uid == 0 {
				err = errno.PasswordIsNotVerified
				return nil, err
			}
			if err != nil {
				return nil, err
			}
			c.Set("user_id", uid)

			return uid, nil
		},
		Authorizator: func(data interface{}, ctx context.Context, c *app.RequestContext) bool {
			if v, ok := data.(float64); ok {
				currentUserId := int64(v)
				c.Set("current_user_id", currentUserId)
				hlog.CtxInfof(ctx, "Token is verified clientIP: "+c.ClientIP())
				return true
			}
			return false
		},
		IdentityKey:   constants.IdentityKey,
		TokenLookup:   "header: Authorization, query: token, cookie: jwt, form: token",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})
}

func UserLoginHandler(ctx context.Context, c *app.RequestContext) {
	once.LoginHandler(ctx, c)
}

func MiddlewareFunc() app.HandlerFunc {
	return once.MiddlewareFunc()
}
```

接下来应用鉴权函数

路由部分：

```go
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

	router.NoRoute(func(ctx context.Context, c *app.RequestContext) {
		c.String(consts.StatusOK, "no route")
	})
	router.NoMethod(func(ctx context.Context, c *app.RequestContext) {
		c.String(consts.StatusOK, "no method")
	})

	router.Spin()
}
```

注册部分：

```go
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
```

启动后，使用如下指令即可访问服务，并获得token：

```shell
curl --location --request POST 'http://127.0.0.1:8080/user/login' \
--header 'User-Agent: Apifox/1.0.0 (https://apifox.com)' \
--header 'Content-Type: application/json' \
--data-raw '{
    "username":"test",
    "password":"123456"
}'
```

