# 业务后端学习与实践

毕业在即，本人现已投身于业务后端的研发，回顾一年来在此领域的学习和实践，写下这篇文章，既是分享自己的一点点收获，也是纪念这一段快乐的时光。因此这既是一篇技术创作，也是一篇属于个人的回忆录，希望以这种方式总结过去的成长，激励自己在未来更加努力。

本文的特点：

1. 使用语言：Go
2. 使用的框架：Hertz、Kitex、Gorm
3. 附带完整的代码实现：
  - 一个简单的文章创作平台： https://github.com/T4t4KAU/webx
  - 其他：(正在开发，敬请期待)

如果对本文有如何的疑问，都可直接邮件联系：microcode1024@gmail.com

## 快速起步

下面会基于Hertz写一个简单的用户注册和登录接口，登录和注册是非常常见的功能。在注册过程中，用户输入用户名、密码以及其他必要的信息，然后发起注册请求。一旦注册成功，用户的账号信息将被添加到系统中。而在登录过程中，用户使用之前注册时所使用的用户名和密码，再加上其他验证信息，即可成功登录。

Hertz是字节跳动研发的HTTP框架，具有高易用、高性能和高扩展性等特点

快速入门：https://www.cloudwego.io/zh/docs/hertz/getting-started/

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

同理实现几个用户查询函数，例如：

通过用户名查询用户信息：

```go
func QueryUserByName(ctx context.Context, username string) (User, error) {
	var user User
	err := dao.WithContext(ctx).Where("username = ?", username).Find(&user).Error
	if err != nil {
		return User{}, err
	}
	if user.Id == 0 {
		return User{}, nil
	}
	return user, nil
}
```

校验用户密码：

```go
func VerifyUser(ctx context.Context, username string, password string) (int64, error) {
	var user User
	err := dao.WithContext(ctx).Where("username = ?", username).Find(&user).Error
	if err != nil {
		return 0, err
	}
	if user.Id == 0 {
		return 0, errno.UserIsNotExistErr
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return 0, err
	}

	return user.Id, nil
}
```

这一层面一般被称为数据库层，数据库层负责与数据库进行交互，包括数据的存储、检索、更新和删除等操作。

### 业务设计

到这里就是服务层，服务层是业务逻辑的核心，负责实现应用程序的业务规则和业务流程。它通常包含与业务相关的代码，如数据处理、业务计算、验证和授权等。服务层的主要目标是将业务逻辑从其他层（如数据库层和处理器层）中分离出来，提供可重用、可测试和可维护的业务功能。

下面实现用户注册的业务逻辑

```go
package service

type UserService struct {
	ctx context.Context
	c   *app.RequestContext
}

func NewUserService(ctx context.Context, c *app.RequestContext) *UserService {
	return &UserService{ctx: ctx, c: c}
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

	user, err := db.QueryUserByName(req.Username)
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
```

这里只要读取请求，然后调用上述写好的数据库接口即可

### 请求处理

这里被称为处理器层，或者说Handler层，处理器层负责处理外部请求和响应，通常是Web应用程序中的请求处理器或控制器。它接收来自客户端的请求，调用适当的服务层方法来处理请求，并生成响应返回给客户端。处理器层的主要目标是处理与外部交互相关的逻辑，如路由解析、参数解析、身份验证和响应构建等。

编写如下函数，形式上要符合 `app.HandlerFunc`

```go
func UserRegister(ctx context.Context, c *app.RequestContext) {
	var req service.UserRegisterReq

	if err := c.Bind(&req); err != nil {
		c.String(http.StatusBadRequest, "param error")
		return
	}

	_, err := service.NewUserService(ctx, c).Register(&req)
	if err != nil {
		c.String(http.StatusInternalServerError, "system error")
		return
	}
	
	auth.UserLogin(ctx, c)
}
```

这里用户输入的密码要做哈希计算后再存入数据库，明文密码直接存到数据库是不安全的，一旦数据库被非法访问或泄露，攻击者可以直接获取用户的密码。这将导致用户的账户和其他相关信息受到威胁，可能导致身份盗窃、欺诈和其他恶意行为。当用户注册成功后，再调用UserLogin函数返回登录的响应信息。

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

JWT 全称叫 Json Web Token，由三部分组成，通过点号（.）分隔开：

1. Header（头部）：包含了关于令牌的元数据和算法信息，通常包括令牌的类型（如 JWT）、所使用的签名算法（如 HMAC SHA256 或 RSA）等。
2. Payload（负载）：包含了要传输的数据，可以是用户的身份信息、权限等。负载可以包含自定义的声明（Claim），也可以包含一些预定义的声明，如过期时间（exp）、发布时间（iat）等。
3. Signature（签名）：使用指定的算法和密钥对头部和负载进行签名，以确保令牌的完整性和真实性。签名可以防止令牌被篡改或伪造。

使用JWT进行鉴权一般流程如下：

1. 用户登录：用户提供凭证进行登录，服务器验证凭证成功后，生成JWT。
2. 令牌传递：服务器将JWT返回给客户端，客户端将其保存在本地。
3. 请求授权：客户端在后续的请求中，将JWT作为Bearer令牌放在请求的`Authorization`头部中。
4. 服务器验证：服务器在接收到请求时，从`Authorization`头部中提取JWT，并进行验证。验证包括检查令牌的有效性、签名是否正确以及令牌是否过期等。
5. 授权访问：如果JWT验证通过，服务器可以使用令牌中的信息来授权用户访问特定的资源或执行特定的操作。

下面完善jwt鉴权功能，在数据层补充一个函数：

```go
func VerifyUser(username string, password string) (int64, error) {
	// 验证密码正确性
    // ......
}
```

该函数接收用户名和密码作为参数，用于校验用户名和密码的正确性

在Hertz中可以如下这样在Middleware中初始化JWT组件：

```go
package auth

var (
	once *jwt.HertzJWTMiddleware
)

func Init() {
	// 创建jwt middleware
	once, _ = jwt.New(&jwt.HertzJWTMiddleware{
		Key:     []byte(constants.SecretKey), // 签名密钥
		Timeout: time.Hour * 24,
        
        // 添加自定义负载信息
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(int64); ok {
				return jwt.MapClaims{
                    // 添加user_id作为负载信息
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
        
        // 登录时触发
		Authenticator: func(ctx context.Context, c *app.RequestContext) (interface{}, error) {
			type LoginParam struct {
				Username string
				Password string
			}

			var param LoginParam
			if err := c.BindAndValidate(&param); err != nil {
				return nil, err
			}
            
            // 验证密码正确性
			uid, err := db.VerifyUser(ctx, param.Username, param.Password)
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
        
        // 已认证用户路由访问权限函数
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

func UserLogin(ctx context.Context, c *app.RequestContext) {
	once.LoginHandler(ctx, c)
}

func MiddlewareFunc() app.HandlerFunc {
	return once.MiddlewareFunc()
}
```

这段代码比较抽象，详情可以见：https://www.cloudwego.io/zh/docs/hertz/tutorials/basic-feature/middleware/jwt/

接下来应用上述代码

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

注册接口：

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
}
```

这样当用户注册成功，也会获得服务端返回的JWT

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

访问一些资源和服务时需要在请求中携带JWT，以获得访问的权限

那么到此为止，简单的登录和注册接口就完成了，但是上述代码仍然还存在很多问题，例如缺少合理的错误处理、日志输出、安全保护等功能，并且接口性能还可再做优化，在下面的代码中会逐步完善。

还可以顺带完成profile和edit接口，用户可以通过用户名获得某个用户的展示信息，也可以编辑自己的展示信息，比如Email、个性签名等，这里可能要牵涉到数据库表信息的扩展，就不做赘述了，相关接口已经在代码里实现。

## 代码生成

可以利用Hertz提供的代码生成功能，快捷地构建项目目录，避免了很多的不必要的工作

首先定义IDL文件：

common.thrift

```thrift
namespace go common

struct User {
  1: required i64 id; // user id
  2: required string name; // user name
  3: required string email // user email
  4: required string signature // user signature
}
```

user.thrift

```thrift
namespace go user

include "common.thrift"

struct UserRegisterReq {
    1: required string username
    2: required string password
}

struct UserRegisterResp {
    1: required i32 status_code
    2: required string status_msg
    3: required i64 user_id
    4: required string token
}

struct UserLoginReq {
    1: required string username
    2: required string password
}

struct UserLoginResp {
    1: required i32 status_code
    2: required string status_msg
    3: required i64 user_id
    4: required string token
}

struct UserProfileReq {
    1: required i64 user_id
    2: required string token
}

struct UserProfileResp {
    1: required i32 status_code
    2: required string status_msg
    3: required common.User user;
}

struct UserEditReq {
    1: required string token
    2: required string email
    3: required string signature
}

struct UserEditResp {
    1: required i32 status_code
    2: required string status_msg
}

service UserService {
    UserRegisterResp Register(1: UserRegisterReq req) (api.post="/user/register")
    UserLoginResp Login(1: UserLoginReq req) (api.post="/user/login")
    UserProfileResp Profile(1: UserProfileReq req) (api.post="/user/profile")
    UserEditResp Edit(1: UserEditReq req) (api.post="/user/edit")
}
```

在项目目录下执行：

```powershell
hz new -module github.com/T4t4KAU/webx -idl idl/user.thrift
go mod tidy
```

即可完成代码生成，下面基于该框架重新编写上述代码，注意最好原先目录下只有idl目录，没有其他目录

生成完上述代码后还可以生成数据库操作相关的代码，首先安装相关依赖：

```powershell
go get -u gorm.io/gen  
```

建立在项目目录下cmd/gen/generate.go:

```go
package main

func connectDB(dsn string) *gorm.DB {
	db, err := gorm.Open(mysql.Open(dsn))
	if err != nil {
		panic(fmt.Errorf("connect db fail: %w", err))
	}
	return db
}

func main() {
	g := gen.NewGenerator(gen.Config{
		OutPath: "../../dal/query",
		Mode:    gen.WithDefaultQuery | gen.WithQueryInterface,
	})

	g.UseDB(connectDB(constant.MySQLDSN))
	g.ApplyBasic(g.GenerateAllTable()...)

	// 执行并生成代码
	g.Execute()
}
```

在目标数据库中创建数据表：

```sql
CREATE TABLE `user` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(255) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `signature` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`)
);
```

在该目录下执行：

```powershell
go run generate.go
```

会在项目目录下生成dal目录，其中包含了生成的代码

其实还有更方便的代码生成方式，只要定义相关的接口，即可将相关函数一并生成，这里就不作过多赘述了

详情请见：https://gorm.io/zh_CN/gen/index.html

目前总体的目录如下所示：

```powershell
.
├── README.md
├── biz
│   ├── handler
│   │   ├── ping.go
│   │   └── user
│   │       └── user_service.go
│   ├── model
│   │   ├── common
│   │   │   └── common.go
│   │   └── user
│   │       └── user.go
│   └── router
│       ├── register.go
│       └── user
│           ├── middleware.go
│           └── user.go
├── build.sh
├── cmd
│   └── gen
│       └── generate.go
├── dal
│   ├── model
│   │   └── tb_user.gen.go
│   └── query
│       ├── gen.go
│       └── tb_user.gen.go
├── go.mod
├── go.sum
├── idl
│   ├── common.thrift
│   └── user.thrift
├── main.go
├── pkg
│   └── constant
│       └── constant.go
├── router.go
├── router_gen.go
└── script
    └── bootstrap.sh
```

使用生成的代码，实现一系列添加和查询接口：

```go
func InsertUser(ctx context.Context, user model.User) error {
	err := query.User.WithContext(ctx).Create(&user)
	if err != nil {
		return err
	}
	return nil
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

// ......
```

在生成的代码框架中，在对应路由上增加路由函数，要修改router/user目录下的文件middleware.go：

```go
func _editMw() []app.HandlerFunc {
	return []app.HandlerFunc{
		auth.MiddlewareFunc(),
	}
}

func _profileMw() []app.HandlerFunc {
	return []app.HandlerFunc{
		auth.MiddlewareFunc(),
	}
}
```

在路由上增加了用户鉴权函数

## 缓存引入

这次的目标是优化接口性能，在优化之前，可以先测试现在接口的性能是怎样的，下面安装一个叫wrk的工具：

```powershell
brew install wrk # MacOS
apt install wrk # Ubuntu
```

`wrk` 是一个用于进行 HTTP 压力测试的开源工具。它是一个命令行工具，用于模拟并测量 HTTP 请求的性能和吞吐量。

查看wrk的使用方法：

```
wrk 4.2.0 [kqueue] Copyright (C) 2012 Will Glozer
Usage: wrk <options> <url>                            
  Options:                                            
    -c, --connections <N>  Connections to keep open   
    -d, --duration    <T>  Duration of test           
    -t, --threads     <N>  Number of threads to use   
                                                      
    -s, --script      <S>  Load Lua script file       
    -H, --header      <H>  Add header to request      
        --latency          Print latency statistics   
        --timeout     <T>  Socket/request timeout     
    -v, --version          Print version details      
                                                      
  Numeric arguments may include a SI unit (1k, 1M, 1G)
  Time arguments may include a time unit (2s, 2m, 2h)
```

-t 表示线程数量，-d 表示持续时间，-c 表示并发数量 -s 表示测试脚本

写一段lua代码作为测试脚本：

```lua
wrk.method="POST"
wrk.headers["Content-Type"] = "application/json"
wrk.body='{"user_id": 1001}'
```

这里只是简单演示，一般情况下并不使用lua脚本

启动后，在项目根目录下执行该指令进行测试：

```powershell
 wrk -t1 -d1s -c2 -s ./script/wrk/user_profile.lua http://127.0.0.1:8888/user/profile
```

含义是指定线程数为1，持续时间为1s 并发数量为2

输出(具体结果视机器而定)：

```
  1 threads and 2 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    38.20us   44.90us   1.57ms   97.65%
    Req/Sec    53.57k     6.87k   56.94k    90.91%
  58619 requests in 1.10s, 13.58MB read
  Non-2xx or 3xx responses: 58619
Requests/sec:  53321.56
Transfer/sec:     12.36MB
```

简单解释一下输出信息的含义：

- Thread Stats：
  - Avg：平均值，表示每个请求的平均性能指标。
  - Stdev：标准差，表示性能指标的波动程度。
  - Max：最大值，表示性能指标的最大值。
  - +/- Stdev：标准差的百分比，表示性能指标的波动程度。
- Latency：
  - Avg：平均延迟，即每个请求的平均响应时间。
  - Stdev：延迟的标准差，表示响应时间的波动程度。
  - Max：最大延迟，表示响应时间的最大值。
- Req/Sec：每秒请求数，表示每秒发送的请求数量。
- 58619 requests in 1.10s, 13.58MB read：在 1.10 秒内发送了 58619 个请求，读取了 13.58MB 的数据。
- Non-2xx or 3xx responses: 58619：非 2xx 或 3xx 响应的请求数，即返回了非成功状态码的请求数。
- Requests/sec: 53321.56：每秒请求数，表示每秒发送的请求数量。
- Transfer/sec: 12.36MB：每秒传输数据量，表示每秒传输的数据量。

再看看登录：

下面做一个简单的性能优化，算是一个基本操作：引入缓存机制，这里要先部署redis组件，同样使用docker来部署:

在docker-compose文件中添加：

```yaml
redis:
image: redis:latest
container_name: redis
ports:
  - "16379:6379"
volumes:
  - ./script/redis/redis.conf:/usr/local/etc/redis/redis.conf
  - ./pkg/data/redis/:/data
command: redis-server /usr/local/etc/redis/redis.conf
restart: always
```

使用docker-compose就可以快速部署redis

安装Go的Redis SDK：

```powershell
go get github.com/redis/go-redis/v9
```

引入缓存就意味着，对于一些查询操作可以先访问缓存，如果缓存没有，再访问数据库，如果缓存中已经存在数据，那么就没必要访问数据库，从而提高了数据查询的效率。但是这样一改其实会带来一系列隐患，比如说，缓存不可用了，那么请求就会都落在数据库上，如果QPS很高的话，有打垮数据库的风险，因此要考虑对数据库的保护，又比如缓存和数据库会不会出现数据不一致，应该如何处理。

除了缓存故障问题，还有数据同步的问题，如何让Redis和MySQL同步更新数据？针对不同的场景有不一样的策略，脱离实际问题讨论解决方案是没有意义的，除此以外，潜在的问题还有很多，后面会慢慢讨论。

当 redis 中不存在要查询的数据，那么就会返回值为redis.Nil的error (如果访问redis失败产生error，可能要另外考虑，这里先这样写)，判断error是否为nil，如果为nil，那么说明缓存中拿到数据可直接返回，反之要去数据库查询。

还有一种做法是当访问缓存出现error(不是redis.Nil)，那么就直接返回不再走下面的流程，这样能很好地保护住数据库，也可以说是一种兜底策略。

实现缓存的接口：

```go
package cache

var expiration = time.Minute * 15

func GetUserById(ctx context.Context, id int64) (common.User, error) {
	key := KeyByUserId(id)
	bytes, err := RD.Get(ctx, key).Bytes()
	if err != nil {
		return common.User{}, err
	}

	var u common.User
	err = sonic.Unmarshal(bytes, &u)
	if err != nil {
		return common.User{}, err
	}
	return u, nil
}

func SetUserById(ctx context.Context, id int64, user common.User) error {
	val, err := sonic.Marshal(user)
	if err != nil {
		return err
	}
	key := KeyByUserId(id)
	return RD.Set(ctx, key, val, expiration).Err()
}

func KeyByUserId(id int64) string {
	return fmt.Sprintf("user:id:%d", id)
}

func KeyByUserName(name string) string {
	return fmt.Sprintf("user:name:%s", name)
}
```

这里使用的json库是sonic，安装：

```powershell
go get github.com/bytedance/sonic  
```

原先的数据库查询作修改：

```go
func (svc *UserService) Profile(req *user.UserProfileReq) (common.User, error) {
	data, err := cache.GetUserById(svc.ctx, req.UserID)
	if err == nil {
		return data, err
	}

	u, err := dal.QueryUserById(svc.ctx, req.UserID)
	if u == (model.User{}) {
		return common.User{}, errno.UserIsNotExistErr
	}
	if err != nil {
		return common.User{}, err
	}

	res := common.User{
		Name:      u.Username,
		Email:     u.Email,
		Signature: u.Signature,
	}

	go func(ctx context.Context) {
		_ = cache.SetUserById(ctx, req.UserID, res)
	}(svc.ctx)

	return res, nil
}
```

重新启动并使用wrk进行性能测试，可以发现速度提高了10%左右。

上述的缓存使用姿势无疑是最简单的一种，实际上应对不同场景还有很多中使用姿势，例如对于高并发场景下可以搭建Redis Cluster，从而保存更多的数据，做到更好的可用性，就算发生单点故障也能继续提供服务，但是这种方案又不适用于大规模集群，因为Redis Cluster采用Goosip协议来传播集群配置的变化，但是在大规模集群下数据传播速度很慢，数据不同步的问题很明显，

加入了缓存后，带来便利的同时也带来了隐患，例如经典的缓存穿透问题，例如大Key问题，例如遇到更新缓存失败但更新数据库成功如何解决，反之数据库更新失败但缓存更新成功又如何解决？这些都是下面要思考并改进的问题。

## 验证方式

之前的登录方式是通过用户名和密码进行登录，这是比较简单和传统的办法了，毫无疑问的是这种方法有很多的缺陷，如今我们可以看到网站的登录方式是五花八门的，已经完全不限于传统的方式。

例如，短信校验作为一种流行的，替代传统密码登录方式的身份验证方法，就具有以下好处：

1. 避免密码泄露风险：传统的密码登录方式存在密码泄露的风险，如果用户的密码被盗取或猜测，攻击者可以直接使用密码登录用户的账户。而短信校验不需要用户输入密码，减少了密码泄露的风险。
2. 简化用户体验：短信校验通常只需要用户提供手机号码，然后接收一条包含验证码的短信。用户无需记住和输入复杂的密码，简化了登录流程，提高了用户体验。
3. 强化安全性：短信校验通常会生成一次性的验证码，有效期较短。这意味着即使攻击者获取了验证码，也只能在有效期内使用，增加了安全性。此外，短信校验还可以结合其他安全措施，如IP限制、设备识别等，进一步提升安全性。
4. 防止密码重用问题：许多用户在不同的网站和应用程序中使用相同的密码，这增加了密码泄露的风险。使用短信校验可以避免用户重复使用密码，每次登录都会生成一个新的验证码。
5. 降低账户被盗风险：由于短信校验需要攻击者同时获取用户的手机号码和接收短信的设备，相对于仅仅获取密码，攻击者更难以成功盗取用户的账户。

常见的还有微信扫码验证，相比于传统的账号密码验证具有以下优势：

1. 方便性：微信扫码验证无需用户手动输入账号和密码，只需使用微信扫描二维码即可完成验证过程。这种方式省去了用户记住和输入账号密码的步骤，提供了更加便捷的验证体验。
2. 安全性：微信扫码验证采用了微信的安全机制，通过微信的身份验证和授权流程来验证用户身份。这种方式可以减少密码泄露的风险，因为用户的敏感信息不需要在第三方应用中传输和存储。
3. 统一性：微信扫码验证使用了微信作为验证平台，用户可以使用自己的微信账号来进行验证，无需创建和记忆额外的账号和密码。这种方式可以提供统一的身份验证机制，减少了用户需要管理的账号数量。
4. 快速性：微信扫码验证通常具有较快的验证速度，用户只需扫描二维码即可完成验证过程，无需等待和输入复杂的账号密码。

因为这两个功能的开发难免会涉及到隐私敏感信息，在此就不作过多讲解了，有兴趣可以参见如下文档：

1. 腾讯云国内短信入门：https://cloud.tencent.com/document/product/382/37745
2. 微信登录开发指南：https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html

## 日志模块

日志在开发和运维中有重要的作用，是排查问题和分析程序运行状态的重要工具

日志是分级别的，常见的日志级别包括以下几个：

1. DEBUG (调试)：最低级别的日志，用于输出详细的调试信息，通常用于开发和调试阶段。
2. INFO (信息)：用于输出一般的信息性消息，例如应用程序的启动、关键操作的开始和结束等。
3. WARN(警告)：用于输出警告信息，表示潜在的问题或异常情况，但不会导致应用程序的中断或错误。
4. ERROR(错误)：用于输出错误信息，表示应用程序遇到了可恢复的错误或异常情况，但仍然可以继续运行。
5. FATAL(致命)：最高级别的日志，用于输出致命错误信息，表示应用程序遇到了无法恢复的严重错误，可能导致应用程序的崩溃或终止。

在Go中，主要使用zap作为日志框架，安装方式：

```powershell
go get -u go.uber.org/zap
```

引入日志模块后，要对程序进行新的改造，例如不应该将error暴露出来，应该使用日志信息来输出

这里推荐先定义一个接口：

```go
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}
```

实现相关接口：

```go
type ZapLogger struct {
	l *zap.Logger
}

func (z *ZapLogger) Debug(msg string, args ...Field) {
	z.l.Debug(msg, z.toZapFields(args)...)
}

func (z *ZapLogger) Info(msg string, args ...Field) {
	z.l.Info(msg, z.toZapFields(args)...)
}

func (z *ZapLogger) Warn(msg string, args ...Field) {
	z.l.Warn(msg, z.toZapFields(args)...)
}

func (z *ZapLogger) Error(msg string, args ...Field) {
	z.l.Warn(msg, z.toZapFields(args)...)
}

func (z *ZapLogger) toZapFields(args []Field) []zap.Field {
	res := make([]zap.Field, 0, len(args))
	for _, arg := range args {
		res = append(res, zap.Any(arg.Key, arg.Value))
	}
	return res
}
```

增加日志输出：

```go
func (svc *UserService) Profile(req *user.UserProfileReq) (common.User, error) {
	// ......

	u, err := dal.QueryUserById(svc.ctx, req.UserID)
	if u == (model.User{}) {
		return common.User{}, errno.UserIsNotExistErr
	}
	if err != nil {
		logger.Warn("Failed to query user by id, error=", err.Error())
		return common.User{}, err
	}
    
	// ......
}

```

Hertz还支持了在系统出入口输出日志信息，所谓出口就是调用第三方模块，入口就是收到请求

定义Handler

```go
func LogRecoveryHandler(c context.Context, ctx *app.RequestContext, err interface{}, stack []byte) {
	hlog.SystemLogger().CtxErrorf(c, "[Recovery] err=%v\nstack=%s", err, stack)
	hlog.SystemLogger().Infof("Client: %s", ctx.Request.Header.UserAgent())
	ctx.AbortWithStatus(consts.StatusInternalServerError)
}
```

使用：

```go
h.Use(recovery.Recovery(recovery.WithRecoveryHandler(logx.LogRecoveryHandler)))
```

## 文章发表

发文章是一个典型的内容生产模块，除此之外还有发照片墙、发视频等

对于内容创作者来说，对文章应该有增删改查的权限，而对读者来说，只用查询。

首先创建对应的数据表，来存储帖子：

```sql
create table article
(
    id        bigint auto_increment
        primary key,
    title     varchar(1024) null,
    content   blob          null,
    author_id bigint        null,
    ctime     bigint        null,
    utime     bigint        null,
    constraint article_user_id_fk
        foreign key (author_id) references user (id)
);

create index article_author_id_index
    on article (author_id);
```

使用gen生成代码，随后定义相关的函数：

```go
func InsertArticle(ctx context.Context, article model.Article) error {
	return query.Article.WithContext(ctx).Create(&article)
}

func QueryArticleById(ctx context.Context, id int64) (*model.Article, error) {
	article, err := query.Article.WithContext(ctx).Where(query.Article.ID.Eq(id)).First()
	if err != nil {
		return &model.Article{}, errno.ErrDatabaseError.WithMessage(err.Error())
	}
	return article, nil
}
```

生成好数据层相关的代码后，开始分析这个功能的需求：

在这个场景中，用户是文章的创作者，从DDD的角度看，在用户领域中，用户是一个实体，是独立存在的，而在文章领域中，用户就称为了值对象，意义为某个文章的创作者。

对于文章的创作者，文章服务至少提供四个接口，发表、编辑、删除和查询，与此同时，文章如果没被删除的话，应该有两种状态：未发表和已发表，未发表可能是用户还在编辑，文章还是草稿，已发表即用户已经确认发表，将显示出来。有些情况下，文章还设置了部分用户不可见，或者文章还有一个在审核的状态，这些情况以及其他复杂的情况暂且不考虑。

同时，这里的文章是纯文本，不会嵌入视频、图片等其他信息。

定义新的IDL：

```thrift
struct Article {
    1: required i64 id;
    2: required i64 author_id
    3: required string title
    4: required string content
}
```

```thrift
namespace go article

include "common.thrift"

struct ArticleCreateReq {
    1: required string title
    2: required string content
    3: required string token
    4: required bool publish
}

struct ArticleCreateResp {
    1: required i64 article_id
    2: required i32 status_code
    3: required string status_msg
}

struct ArticlePublishReq {
    1: required i64 article_id
}

struct ArticlePublishResp {
    1: required i32 status_code
    2: required string status_msg
}

struct ArticleDeleteReq {
    1: required i64 article_id
    2: required string token
}

struct ArticleDeleteResp {
    1: required i32 status_code
    2: required string status_msg
}

struct ArticleEditReq {
    1: required i64 article_id
    2: optional string title
    3: optional string content
    4: required string token
}

struct ArticleEditResp {
    1: required i32 status_code
    2: required string status_msg
}

struct ArticleInfoReq {
    1: required i64 article_id
}

struct ArticleInfoResp {
    1: required i32 status_code
    2: required string status_msg
    3: optional common.Article article,
}

struct ArticleHideReq {
    1: required i64 article_id
    2: required string token
}

struct ArticleHideResp {
    1: required i32 status_code
    2: required string status_msg
}


service ArticleService {
    ArticlePublishResp Publish(1: ArticlePublishReq request) (api.post="/article/publish"),
    ArticleDeleteResp Delete(1: ArticleDeleteReq request) (api.post="/article/delete"),
    ArticleEditResp Edit(1: ArticleEditReq request) (api.post="/article/edit"),
    ArticleInfoResp GetInfo(1: ArticleInfoReq request) (api.get="/article/info"),
    ArticleCreateResp Create(1: ArticleCreateReq request) (api.post="/article/create")
    ArticleHideResp Hide(1: ArticleHideReq request) (api.get="/article/hide")
}
```

更新代码：

```powershell
hz update -idl idl/article.thrift -module github.com/T4t4KAU/webx
```

对于一篇全新的文章，用户在创建的时候调用Create接口，这时候会生成一篇文章对应的id以及其他信息，并将数据插入数据库，如果用户创建后没有发表，只是保存的话，那么就设置published为false，如果发表的话就标记为true。如果修改文章的内容，那么就调用Edit接口，将新的内容更新到数据库，如果删除的话就调用Delete接口，如果查询某个文章的信息，那么就调用GetInfo接口，如果想要隐藏已经发表的某篇文章可以使用Hide接口。

实现业务逻辑：

```go
package service

type ArticleService struct {
	ctx context.Context
	c   *app.RequestContext
}

func NewArticleService(ctx context.Context, c *app.RequestContext) *ArticleService {
	return &ArticleService{
		ctx: ctx,
		c:   c,
	}
}

func (svc *ArticleService) Create(req *article.ArticleCreateReq) error {
	id, _ := svc.c.Get("current_user_id")

	// 初始化文章 插入数据库
	err := dal.InsertArticle(svc.ctx, model.Article{
		Title:     req.Title,
		Content:   []byte(req.Content),
		AuthorID:  id.(int64),
		Ctime:     time.Now().UnixNano(),
		Utime:     time.Now().UnixNano(),
		Published: req.Publish,
	})
	if err != nil {
		logger.Warn("Failed to insert article to database, error=" + err.Error())
		return err
	}
	return nil
}

func (svc *ArticleService) Publish(req *article.ArticlePublishReq) error {
	id, _ := svc.c.Get("current_user_id")
	ar, err := dal.QueryArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		logger.Warn("Failed to query article by id, error=" + err.Error())
		return err
	}
	if id != ar.AuthorID {
		return errno.ArticlePermssionDenied
	}

	ar.Published = true
	err = dal.UpdateArticleById(svc.ctx, ar)
	if err != nil {
		logger.Warn("Fail to update article by id, error=" + err.Error())
		return err
	}
	return nil
}

func (svc *ArticleService) Delete(req *article.ArticleDeleteReq) error {
	id, _ := svc.c.Get("current_user_id")
	ar, err := dal.QueryArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		logger.Warn("Failed to query article by id, error=" + err.Error())
		return err
	}
	if ar.AuthorID != id {
		return errno.ArticlePermssionDenied
	}
	err = dal.DeleteArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		logger.Warn("Failed to delete article by id, error=" + err.Error())
		return err
	}
	return nil
}

func (svc *ArticleService) Edit(req *article.ArticleEditReq) error {
	id, _ := svc.c.Get("current_user_id")
	ar, err := dal.QueryArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		logger.Warn("Failed to query article by id, error=" + err.Error())
		return err
	}
	if ar.AuthorID != id {
		return errno.ArticlePermssionDenied
	}

	ar.Title = *req.Title
	ar.Content = []byte(*req.Content)
	ar.Utime = time.Now().UnixNano()

	// 更新数据库数据
	err = dal.UpdateArticleById(svc.ctx, ar)
	if err != nil {
		logger.Warn("Fail to update article by id, error=" + err.Error())
		return err
	}
	return nil
}

func (svc *ArticleService) GetInfo(req *article.ArticleInfoReq) (common.Article, error) {
	ar, err := dal.QueryArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		return common.Article{}, err
	}
	if ar == (&model.Article{}) {
		return common.Article{}, errno.ArticleIsNotExistErr
	}
	return common.Article{
		AuthorID: ar.AuthorID,
		Title:    ar.Title,
		Content:  string(ar.Content),
	}, nil
}

func (svc *ArticleService) Hide(req *article.ArticleHideReq) error {
	ar, err := dal.QueryArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		return err
	}
	if ar == (&model.Article{}) {
		return errno.ArticleIsNotExistErr
	}

	ar.Published = false
	ar.Utime = time.Now().UnixNano()
	err = dal.UpdateArticleById(svc.ctx, ar)
	if err != nil {
		return err
	}
	return nil
}
```

回过头重新看这个场景，曾经有人说，MySQL不适合存文档，而MongoDB更适合存文档之类的数据。事实上MongoDB确实在读取大型文档时有更好的性能。

详细来说，MongoDB有以下几点特性：

1. 文档数据库：MongoDB是一种文档数据库，使用类似JSON的BSON（二进制JSON）格式来存储数据。它以文档的形式组织数据，每个文档可以有不同的结构，使得数据模型更加灵活。
2. 无模式设计：MongoDB是一个无模式或动态模式的数据库，不需要预先定义表结构。这意味着可以直接存储不同结构的文档，而无需事先定义模式。
3. 高性能：MongoDB具有高性能的读写操作，特别是在大规模数据和高并发访问的情况下。它支持水平扩展，可以通过添加更多的节点来提高性能和容量。
4. 分布式存储：MongoDB支持分布式存储，可以在多个节点上分布数据。这种分布式架构提供了高可用性和容错性，以及负载均衡和故障恢复能力。
5. 强大的查询功能：MongoDB提供丰富的查询功能，包括灵活的查询语法、索引支持和聚合管道。它支持复杂的查询操作，如范围查询、文本搜索和地理空间查询等。
6. 支持复制和故障恢复：MongoDB支持数据复制和自动故障恢复。它可以创建主从复制集，将数据复制到多个节点，以提供数据冗余和高可用性。
7. 内置的分片功能：MongoDB支持数据分片，可以将数据分布到多个分片上。这种分片架构允许处理大量的数据和高并发访问，并提供水平扩展的能力。
8. 丰富的工具和驱动程序：MongoDB提供了丰富的工具和驱动程序，以便于开发人员使用和管理数据库。它支持多种编程语言的驱动程序，并提供了命令行工具和图形界面工具来管理和监控数据库。

不同于MySQL的是，MongoDB用不着预先定义模型，并且可以很轻松地横向扩展。下面要实现对大量文章的查询，此处可以考虑引入MongoDB来存储文章内容，MySQL用于存储元数据。要安装mongodb同样可以使用docker安装，这里就不作过多赘述了。

同样地，下面也要对文章查询应用缓存，对于文章的作者来说，一般要用到两个接口：

- 列表接口：在自己的创作中心能看到自己发表的所有的文章，这是分页展示的，不可能一次性返回所有数据
- 详情接口：作者可以查看文章的全部内容

对于读者来说：

- 搜索接口：读者可以搜索文章
- 推荐接口：当读者打开首页时，系统根据用户喜好来推荐文章
- 阅读接口：读者选中某篇文章可以查看文章全部内容

当用户拿到一个文章列表，那么很大的概率会访问第一篇文章，可以提前将这部分数据加载到缓存并设置过期时间，对于超长文本就不缓存全部内容了。如果在文章发表的时候就立刻会被访问，也可以提前把文章缓存到Redis。如果缓存空间大小达到阈值，必然要淘汰部分数据，可以用LFU淘汰不怎么被访问的数据，也可以淘汰占用空间比较大的文章，淘汰策略要基于场景进行设计。
