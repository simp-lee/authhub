// Package authhub is a unified third-party OAuth login library for Go.
//
// It provides a single [Provider] interface that abstracts away platform-specific
// differences, letting you authenticate users via WeChat, QQ, Alipay, and more
// with a consistent API. The library has zero external dependencies and is
// framework-agnostic — use it with net/http, Gin, Echo, or any other router.
//
// # Supported Providers
//
//   - WeChat PC QR Code Login — [NewWechatWeb]
//   - WeChat Official Account (MP) — [NewWechatMP]
//   - WeChat Mini Program — [NewWechatMini]
//   - QQ — [NewQQ]
//   - Alipay — [NewAlipay]
//
// # Quick Start
//
// The typical OAuth flow consists of four steps: create a provider, generate
// an authorization URL, exchange the callback code for a token, and fetch
// the user's profile.
//
//	// 1. Create a provider (WeChat PC as an example).
//	provider, err := authhub.NewWechatWeb(appID, secret, redirectURL)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// 2. Generate the authorization URL and redirect the user.
//	authURL, err := provider.AuthURL(state)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Redirect user to authURL ...
//
//	// 3. In the callback handler, exchange the code for a token.
//	token, err := provider.ExchangeCode(ctx, code)
//	if err != nil {
//	    var authErr *authhub.AuthError
//	    if errors.As(err, &authErr) {
//	        log.Printf("provider=%s kind=%s msg=%s", authErr.Provider, authErr.Kind, authErr.Message)
//	    }
//	    log.Fatal(err)
//	}
//
//	// 4. Fetch user info.
//	user, err := provider.GetUserInfo(ctx, token)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(user.Nickname, user.Avatar)
//
// # Error Handling
//
// All errors returned by authhub are of type [*AuthError] which carries
// structured fields (Kind, Provider, Code, Message) so you can programmatically
// inspect failures. Sentinel errors such as [ErrInvalidCode] and [ErrNetwork]
// work with [errors.Is] for convenient matching.
//
// # Options
//
// Provider constructors accept functional [Option] values to customize behavior:
//
//	provider, err := authhub.NewWechatWeb(appID, secret, redirectURL,
//	    authhub.WithHTTPClient(customClient),
//	    authhub.WithLogger(myLogger),
//	)
//
// Authorization methods accept [AuthOption] values for per-request settings:
//
//	authURL, err := provider.AuthURL(state, authhub.WithScope("snsapi_userinfo"))
//
// For detailed documentation and additional examples, see the project README at
// https://github.com/simp-lee/authhub.
package authhub
