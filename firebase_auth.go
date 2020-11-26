package ginfirebaseauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/gin-gonic/gin"
	"google.golang.org/api/option"
)

const valName = "FIREBASE_ID_TOKEN"

// FirebaseAuthMiddleware is middleware for Firebase Authentication
type FirebaseAuthMiddleware struct {
	cli           *auth.Client
	unAuthorized  func(c *gin.Context)
	useFakeTokens bool
}

// New is constructor of the middleware
func New(credFileName string, unAuthorized func(c *gin.Context), useFakeTokens bool) (*FirebaseAuthMiddleware, error) {
	if useFakeTokens {
		return &FirebaseAuthMiddleware{
			cli:           nil,
			unAuthorized:  unAuthorized,
			useFakeTokens: useFakeTokens,
		}, nil
	}

	opt := option.WithCredentialsFile(credFileName)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, err
	}
	auth, err := app.Auth(context.Background())
	if err != nil {
		return nil, err
	}
	return &FirebaseAuthMiddleware{
		cli:           auth,
		unAuthorized:  unAuthorized,
		useFakeTokens: useFakeTokens,
	}, nil
}

// MiddlewareFunc is function to verify token
func (fam *FirebaseAuthMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		token := strings.Replace(authHeader, "Bearer ", "", 1)
		idToken, err := fam.verifyToken(token)
		if err != nil {
			if fam.unAuthorized != nil {
				fam.unAuthorized(c)
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{
					"status":  http.StatusUnauthorized,
					"message": http.StatusText(http.StatusUnauthorized),
				})
			}
			return
		}
		c.Set(valName, idToken)
		c.Next()
	}
}

func (fam *FirebaseAuthMiddleware) verifyToken(token string) (*auth.Token, error) {
	if fam.useFakeTokens {
		if token == "bad" {
			return nil, errors.New("bad token [test-mode]")
		}
		//TODO: enrich the fake token with more data
		return &auth.Token{
			UID: "test",
		}, nil
	}
	return fam.cli.VerifyIDToken(context.Background(), token)
}

// ExtractClaims extracts claims
func ExtractClaims(c *gin.Context) *auth.Token {
	idToken, ok := c.Get(valName)
	if !ok {
		return new(auth.Token)
	}
	return idToken.(*auth.Token)
}
