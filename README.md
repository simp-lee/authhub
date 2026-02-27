# AuthHub

统一的第三方 OAuth 登录 Go 库，零外部依赖，框架无关。

通过统一的 `Provider` 接口抽象不同平台的差异，让你用一致的 API 完成用户认证。可搭配 `net/http`、Gin、Echo 或任何其他路由框架使用。

## 支持的 Provider

| Provider | 构造函数 | 说明 |
| --- | --- | --- |
| 微信 PC 扫码登录 | `NewWechatWeb` | 开放平台网站应用 |
| 微信公众号 | `NewWechatMP` | 公众号网页授权 |
| 微信小程序 | `NewWechatMini` | 小程序 `wx.login()` 登录 |
| QQ | `NewQQ` | QQ 互联 OAuth 登录 |
| 支付宝 | `NewAlipay` | 支持公钥模式和证书模式 |

## 安装

```bash
go get github.com/simp-lee/authhub
```

要求 Go 1.21+，零外部依赖。

## 快速开始

以微信 PC 扫码登录为例，OAuth 流程分为四步：

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/simp-lee/authhub"
)

func main() {
	// 1. 创建 Provider
	provider, err := authhub.NewWechatWeb("your-app-id", "your-secret", "https://example.com/callback")
	if err != nil {
		log.Fatal(err)
	}

	// 2. 生成授权 URL，引导用户跳转
	state, _ := authhub.GenerateState()
	authURL, err := provider.AuthURL(state)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("请访问:", authURL)

	// 3. 在回调处理器中，用 code 换取 token
	ctx := context.Background()
	code := "callback-code" // 从回调参数中获取
	token, err := provider.ExchangeCode(ctx, code)
	if err != nil {
		var authErr *authhub.AuthError
		if errors.As(err, &authErr) {
			log.Printf("provider=%s kind=%s msg=%s", authErr.Provider, authErr.Kind, authErr.Message)
		}
		log.Fatal(err)
	}

	// 4. 获取用户信息
	user, err := provider.GetUserInfo(ctx, token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("昵称:", user.Nickname, "头像:", user.Avatar)
}
```

## 各 Provider 使用示例

### 微信 PC 扫码登录

```go
provider, err := authhub.NewWechatWeb("appID", "secret", "https://example.com/callback")
if err != nil {
    log.Fatal(err)
}

state, _ := authhub.GenerateState()
authURL, _ := provider.AuthURL(state)
// 将用户重定向到 authURL

// 回调时
token, err := provider.ExchangeCode(ctx, code)
user, err := provider.GetUserInfo(ctx, token)
```

### 微信公众号

```go
provider, err := authhub.NewWechatMP("appID", "secret", "https://example.com/callback")
if err != nil {
    log.Fatal(err)
}

// 默认 scope 为 "snsapi_userinfo"（弹出授权页面）
state, _ := authhub.GenerateState()
authURL, _ := provider.AuthURL(state)

// 静默授权（仅获取 OpenID，不弹窗）
authURL, _ = provider.AuthURL(state, authhub.WithScope("snsapi_base"))

// 回调时
token, err := provider.ExchangeCode(ctx, code)
user, err := provider.GetUserInfo(ctx, token)
```

### 微信小程序

> **特殊说明：**
> - 小程序没有浏览器重定向流程，不支持 `AuthURL()`，调用会返回 `ErrUnsupported` 错误
> - 不支持 `RefreshToken()`
> - 微信已废弃小程序服务端获取用户昵称头像的接口，`GetUserInfo()` 仅返回 `OpenID` 和 `UnionID`
> - 前端通过 `wx.login()` 获取 code 后传给后端

```go
provider, err := authhub.NewWechatMini("appID", "secret")
if err != nil {
    log.Fatal(err)
}

// 前端通过 wx.login() 获取的 code
token, err := provider.ExchangeCode(ctx, code)
if err != nil {
    log.Fatal(err)
}

// token.OpenID  — 用户唯一标识
// token.UnionID — 跨应用唯一标识（需在开放平台绑定）
// token.Raw["session_key"] — 会话密钥

// GetUserInfo 仅返回 OpenID 和 UnionID
user, err := provider.GetUserInfo(ctx, token)
```

### QQ 登录

```go
provider, err := authhub.NewQQ("appID", "appKey", "https://example.com/callback")
if err != nil {
    log.Fatal(err)
}

state, _ := authhub.GenerateState()
authURL, _ := provider.AuthURL(state)
// 将用户重定向到 authURL

// 回调时
token, err := provider.ExchangeCode(ctx, code)
user, err := provider.GetUserInfo(ctx, token)
```

### 支付宝（公钥模式）

```go
provider, err := authhub.NewAlipay(
    "appID",
    "应用私钥内容",
    "https://example.com/callback",
    authhub.WithAlipayPublicKey("支付宝公钥内容"),
)
if err != nil {
    log.Fatal(err)
}

state, _ := authhub.GenerateState()
authURL, _ := provider.AuthURL(state)
// 将用户重定向到 authURL

// 回调时
token, err := provider.ExchangeCode(ctx, code)
user, err := provider.GetUserInfo(ctx, token)
```

### 支付宝（证书模式）

```go
provider, err := authhub.NewAlipay(
    "appID",
    "应用私钥内容",
    "https://example.com/callback",
    authhub.WithCertMode(
        appCertContent,    // 应用公钥证书内容
        alipayCertContent, // 支付宝公钥证书内容
        rootCertContent,   // 支付宝根证书内容
    ),
)
if err != nil {
    log.Fatal(err)
}

state, _ := authhub.GenerateState()
authURL, _ := provider.AuthURL(state)

token, err := provider.ExchangeCode(ctx, code)
user, err := provider.GetUserInfo(ctx, token)
```

## 移动端使用说明

`ExchangeCode()` 对 Web 端和移动端获取的 code 通用。移动端（如 APP 内通过微信 SDK 拉起授权、QQ SDK 授权等）获取到的 code 可直接传给后端使用同一个 `ExchangeCode()` 方法换取 token，无需区分来源：

```go
// 移动端 SDK 获取的 code 和 Web 回调获取的 code 用法完全相同
token, err := provider.ExchangeCode(ctx, mobileCode)
if err != nil {
    log.Fatal(err)
}
user, err := provider.GetUserInfo(ctx, token)
```

## 错误处理

除极少数底层错误（例如 `GenerateState()` 的随机数读取失败）外，authhub 对外返回的业务错误均为 `*AuthError` 类型，携带结构化信息：

```go
type AuthError struct {
    Kind     ErrorKind // 错误分类
    Provider string    // Provider 名称，如 "wechat_web"、"alipay"
    Code     string    // 平台错误码（可选）
    Message  string    // 可读的错误描述
    Err      error     // 底层错误（可选）
}
```

### 使用 errors.Is 匹配错误类型

```go
token, err := provider.ExchangeCode(ctx, code)
if err != nil {
    if errors.Is(err, authhub.ErrInvalidCode) {
        // 授权码无效或过期
        log.Println("授权码无效，请重新授权")
    } else if errors.Is(err, authhub.ErrNetwork) {
        // 网络错误
        log.Println("网络异常，请稍后重试")
    } else if errors.Is(err, authhub.ErrTokenExpired) {
        // Token 已过期
        log.Println("Token 已过期，请刷新")
    } else if errors.Is(err, authhub.ErrSignature) {
        // 签名验证失败（支付宝）
        log.Println("签名验证失败")
    } else if errors.Is(err, authhub.ErrUnsupported) {
        // 不支持的操作
        log.Println("该操作不被支持")
    }
    return
}
```

### 使用 errors.As 提取详细信息

```go
token, err := provider.ExchangeCode(ctx, code)
if err != nil {
    var authErr *authhub.AuthError
    if errors.As(err, &authErr) {
        log.Printf("provider=%s kind=%s code=%s msg=%s",
            authErr.Provider, authErr.Kind, authErr.Code, authErr.Message)
    }
    return
}
```

### 哨兵错误列表

| 哨兵错误 | 对应 Kind | 说明 |
| --- | --- | --- |
| `ErrNetwork` | `network` | 网络错误（连接超时、DNS 解析失败等） |
| `ErrInvalidCode` | `invalid_code` | 授权码无效或回调参数校验失败 |
| `ErrTokenExpired` | `token_expired` | Access Token 或 Refresh Token 已过期 |
| `ErrSignature` | `signature` | 签名验证失败 |
| `ErrPlatform` | `platform` | 平台返回的业务错误 |
| `ErrUnsupported` | `unsupported` | 不支持的操作 |
| `ErrInvalidConfig` | `invalid_config` | 配置无效或不完整 |

## State / CSRF 防护

authhub 提供内置的 state 生成和验证工具，防止 CSRF 攻击：

```go
// 生成随机 state（32 字节随机数的 base64url 编码）
state, err := authhub.GenerateState()
if err != nil {
    log.Fatal(err)
}

// 将 state 存入 session 或其他存储
session.Set("oauth_state", state)

// 生成授权 URL
authURL, _ := provider.AuthURL(state)

// ... 用户完成授权后回调 ...

// 验证 state（时序安全比较）
expectedState := session.Get("oauth_state")
if err := authhub.ValidateState(expectedState, callbackState); err != nil {
    // state 不匹配，可能遭受 CSRF 攻击
    log.Fatal(err)
}
```

## Token 管理

### 检查 Token 是否过期

```go
token, _ := provider.ExchangeCode(ctx, code)

// IsExpired 在 ExpiresAt 为零值或早于当前时间时返回 true
if token.IsExpired() {
    // 刷新 token
	newToken, err := provider.RefreshToken(ctx, token.RefreshToken)
    if err != nil {
        log.Fatal(err)
    }
    token = newToken
}
```

### 微信 Token 在线验证

`CheckWechatToken` 调用微信 `sns/auth` 接口在线验证 access token 是否仍然有效：

```go
valid, err := authhub.CheckWechatToken(ctx, token.AccessToken, token.OpenID)
if err != nil {
	log.Fatal(err) // 参数错误、网络错误或响应解析失败时返回 error
}
if !valid {
    // token 已失效，刷新
	newToken, err := provider.RefreshToken(ctx, token.RefreshToken)
    if err != nil {
        log.Fatal(err)
    }
    token = newToken
}
```

### 刷新 Token

```go
newToken, err := provider.RefreshToken(ctx, token.RefreshToken)
if err != nil {
    if errors.Is(err, authhub.ErrUnsupported) {
        // 小程序不支持 RefreshToken
        log.Println("该 provider 不支持刷新 token")
    }
    log.Fatal(err)
}
```

## 自定义选项

### 自定义 HTTP Client

```go
import "net/http"

customClient := &http.Client{
    Timeout: 30 * time.Second,
}

provider, err := authhub.NewWechatWeb("appID", "secret", "https://example.com/callback",
    authhub.WithHTTPClient(customClient),
)
```

### 自定义 Logger

实现 `authhub.Logger` 接口即可注入自定义日志：

```go
type Logger interface {
    Debug(msg string, args ...any)
    Info(msg string, args ...any)
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
}
```

示例：

```go
// 使用 slog 作为日志后端
type SlogLogger struct {
    logger *slog.Logger
}

func (l *SlogLogger) Debug(msg string, args ...any) { l.logger.Debug(msg, args...) }
func (l *SlogLogger) Info(msg string, args ...any)  { l.logger.Info(msg, args...) }
func (l *SlogLogger) Warn(msg string, args ...any)  { l.logger.Warn(msg, args...) }
func (l *SlogLogger) Error(msg string, args ...any) { l.logger.Error(msg, args...) }

provider, err := authhub.NewWechatWeb("appID", "secret", "https://example.com/callback",
    authhub.WithLogger(&SlogLogger{logger: slog.Default()}),
)
```

### CheckWechatToken 也支持自定义选项

```go
valid, err := authhub.CheckWechatToken(ctx, accessToken, openID,
    authhub.WithHTTPClient(customClient),
    authhub.WithLogger(myLogger),
)
```

## 在 Web 框架中集成

以下是一个完整的 `net/http` 集成示例：

```go
package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/simp-lee/authhub"
)

var wechatProvider authhub.Provider

func init() {
	var err error
	wechatProvider, err = authhub.NewWechatWeb("appID", "secret", "https://example.com/callback")
	if err != nil {
		log.Fatal(err)
	}
}

// loginHandler 引导用户跳转到微信授权页
func loginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := authhub.GenerateState()
	if err != nil {
		http.Error(w, "生成 state 失败", http.StatusInternalServerError)
		return
	}

	// 实际项目中应将 state 存入 session
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})

	authURL, err := wechatProvider.AuthURL(state)
	if err != nil {
		http.Error(w, "生成授权链接失败", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// callbackHandler 处理微信回调
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// 验证 state
	cookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "缺少 state", http.StatusBadRequest)
		return
	}

	callbackState := r.URL.Query().Get("state")
	if err := authhub.ValidateState(cookie.Value, callbackState); err != nil {
		http.Error(w, "state 验证失败", http.StatusBadRequest)
		return
	}

	// 用 code 换取 token
	code := r.URL.Query().Get("code")
	ctx := r.Context()

	token, err := wechatProvider.ExchangeCode(ctx, code)
	if err != nil {
		var authErr *authhub.AuthError
		if errors.As(err, &authErr) {
			log.Printf("OAuth 错误: provider=%s kind=%s msg=%s", authErr.Provider, authErr.Kind, authErr.Message)
		}
		http.Error(w, "登录失败", http.StatusInternalServerError)
		return
	}

	// 获取用户信息
	user, err := wechatProvider.GetUserInfo(ctx, token)
	if err != nil {
		http.Error(w, "获取用户信息失败", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "欢迎, %s!", user.Nickname)
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## 许可证

[MIT](LICENSE)
