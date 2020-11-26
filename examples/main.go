package main

import (
	"fmt"
	"net/http"

	ginfirebaseauth "github.com/bettyenterprises/gin-firebase-auth"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.New()
	middleware, err := ginfirebaseauth.New("../credentials.json", nil)
	if err != nil {
		panic(err)
	}
	auth := r.Group("/auth")
	auth.Use(middleware.MiddlewareFunc())
	auth.GET("/", func(c *gin.Context) {
		claims := ginfirebaseauth.ExtractClaims(c)
		fmt.Println(claims)
		c.String(http.StatusOK, "success")
	})
	r.Run()
}
