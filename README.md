# 业务后端开发与实践

毕业在即，本人现已投身于业务后端的研发，回顾一年来在此领域的学习和实践，写下这篇文章，既是分享自己的一点点收获，也是纪念这一段快乐的时光。因此这既是一篇技术创作，也是一篇属于个人的回忆录，希望以这种方式总结过去的成长，激励自己在未来更加努力。

本文的特点：

1. 使用语言：Go
2. 使用的框架：Hertz、Kitex、Gorm
3. 附带完整的代码实现：https://github.com/T4t4KAU/webx

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

这里用户输入的密码要做哈希计算后再存入数据库，明文密码直接存到数据库是不安全的，一旦数据库被非法访问或泄露，攻击者可以直接获取用户的密码。这将导致用户的账户和其他相关信息受到威胁，可能导致身份盗窃、欺诈和其他恶意行为。

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

下面完善jwt鉴权功能，在数据层补充一个函数：

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

在Hertz中可以如下这样在Middleware中初始化JWT组件：

```go
package auth

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

即可完成代码生成，下面基于该框架重新编写上述代码

## 领域驱动

领域驱动设计，简称为DDD，与上述传统的MVC架构有一些不同之处，显然DDD更要强调将业务置于中心，通过深入理解业务需求和与领域专家的合作，将业务规则和业务逻辑转化为可执行的领域模型。

DDD有助于更好地理解和满足业务需求，提供更加贴合业务的解决方案。通过将领域模型划分为聚合根、实体、值对象等组件，将业务逻辑封装在领域对象中，实现了模块化和解耦。这使得系统更加灵活、可维护和可扩展，不会受到底层技术和外部因素的影响。



## 缓存机制

这次的目标是优化接口性能，在优化之前，可以先测试现在接口的性能是怎样的，可以安装一个叫wrk的工具：

```powershell
brew install wrk # MacOS
apt install wrk # Ubuntu
```

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
wrk.body='{"username":"test", "password": "123456"}'
```

这里只是简单演示，一般情况下并不使用lua脚本

启动后，在项目根目录下执行该指令进行测试：

```powershell
 wrk -t1 -d1s -c2 -s ./script/wrk/register.lua http://127.0.0.1:8080/user/register
```

含义是指定线程数为1，持续时间为1s 并发数量为2

输出(具体结果视机器而定)：

```
Running 1s test @ http://127.0.0.1:8080/user/register
  1 threads and 2 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.18ms    1.86ms  19.17ms   92.28%
    Req/Sec   499.73    110.01   570.00     90.91%
  547 requests in 1.10s, 184.83KB read
Requests/sec:    497.10
Transfer/sec:    167.97KB
```

简单解释一下输出信息的含义：

- `Thread Stats`：线程统计信息，包括平均值（Avg）、标准差（Stdev）、最大值（Max）和标准差百分比（+/- Stdev）。
- `Latency`：延迟统计信息，表示每个请求的平均延迟时间。在这个例子中，平均延迟为4.18毫秒，标准差为1.86毫秒，最大延迟为19.17毫秒。标准差百分比（+/- Stdev）表示延迟值在平均值的正负标准差范围内的百分比。
- `Req/Sec`：每秒请求数，表示在测试期间平均每秒处理的请求数。在这个例子中，平均每秒处理的请求数为499.73个请求，标准差为110.01，最大请求数为570个请求。标准差百分比（+/- Stdev）表示请求数在平均值的正负标准差范围内的百分比。
- `547 requests in 1.10s, 184.83KB read`：在测试期间总共发送了547个请求，总共读取了184.83KB的数据。
- `Requests/sec`：每秒请求数，表示在测试期间平均每秒处理的请求数。在这个例子中，平均每秒处理的请求数为497.10个请求。
- `Transfer/sec`：每秒传输速率，表示在测试期间平均每秒传输的数据量。在这个例子中，平均每秒传输的数据量为167.97KB。

再看看登录：

执行：

```powershell
wrk -t1 -d1s -c2 -s ./script/wrk/register.lua http://127.0.0.1:8080/user/login   
```

结果：

```go
Running 1s test @ http://127.0.0.1:8080/user/login
  1 threads and 2 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.56ms  489.54us   6.83ms   85.20%
    Req/Sec     1.30k   189.28     1.54k    81.82%
  1419 requests in 1.10s, 472.54KB read
Requests/sec:   1289.62
Transfer/sec:    429.45KB
```

登录的性能显然要高很多，这其中有很多原因，比如说用户登录只牵涉读数据库，而MySQL的存储引擎InnoDB的核心数据结构是B+树，查询性能是高于写入性能的，同时登录也不像注册一样涉及哈希计算。

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

引入缓存就意味着，对于一些查询操作可以先访问缓存，如果缓存没有，再访问数据库，如果缓存中已经存在数据，那么就没必要访问数据库，从而提高了数据查询的效率。但是这样一改就会引发很多潜在的问题，后面再慢慢讨论。

原来的代码结构要做一些修改，引入repository和domain的概念，接着就可以方便地引入缓存模块。

在软件开发中，Domain 是指一个特定的业务领域或问题域，它涉及到特定领域的业务规则、概念、流程和术语等。领域是对特定业务领域的抽象和建模，它关注解决特定领域的业务需求和问题。

Repository是指仓储层，它是在领域层和数据访问层之间的一个接口层，用于封装对数据的访问和操作。Repository提供了一组抽象的方法，用于定义领域对象的持久化操作，例如保存、更新、删除和查询等。Repository的目标是将领域层与数据访问层解耦，使领域层不依赖于具体的数据访问实现，从而提高代码的可测试性和可维护性。

数据库和缓存的操作统一放入repository，而对于一个用户登录注册功能来说，领域是指与用户相关的业务领域，包括用户身份验证、用户注册、用户信息管理等。在这个领域中，用户是核心概念，涉及到用户的身份验证、用户的注册流程、用户的登录状态管理等。

当 redis 中不存在要查询的数据，那么就会返回 为redis.Nil的error (如果访问redis失败产生error，可能要另外考虑，这里先这样写)，判断error是否为nil，如果为nil，那么说明缓存中拿到数据可直接返回，反之要去数据库查询。

加入了缓存后又会引出很多问题，例如经典的缓存穿透问题，例如大Key问题，例如遇到更新缓存失败但更新数据库成功如何解决，反之数据库更新失败但缓存更新成功又如何解决？这些都是下面要思考并改进的问题。

## 短信验证

之前的登录方式是通过用户名和密码进行登录，这是比较简单和传统的办法了，毫无疑问的是这种方法有很多的缺陷，如今我们可以看到网站的登录方式是五花八门的，已经完全不限于传统的方式。

短信校验作为一种流行的，替代传统密码登录方式的身份验证方法，就具有以下好处：

1. 避免密码泄露风险：传统的密码登录方式存在密码泄露的风险，如果用户的密码被盗取或猜测，攻击者可以直接使用密码登录用户的账户。而短信校验不需要用户输入密码，减少了密码泄露的风险。
2. 简化用户体验：短信校验通常只需要用户提供手机号码，然后接收一条包含验证码的短信。用户无需记住和输入复杂的密码，简化了登录流程，提高了用户体验。
3. 强化安全性：短信校验通常会生成一次性的验证码，有效期较短。这意味着即使攻击者获取了验证码，也只能在有效期内使用，增加了安全性。此外，短信校验还可以结合其他安全措施，如IP限制、设备识别等，进一步提升安全性。
4. 防止密码重用问题：许多用户在不同的网站和应用程序中使用相同的密码，这增加了密码泄露的风险。使用短信校验可以避免用户重复使用密码，每次登录都会生成一个新的验证码。
5. 降低账户被盗风险：由于短信校验需要攻击者同时获取用户的手机号码和接收短信的设备，相对于仅仅获取密码，攻击者更难以成功盗取用户的账户。