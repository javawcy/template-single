package cmd

import (
	"code.topwidgets.cn/maoerduo-server/ce-core/middleware"
	"context"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcmd"

	"github.com/gogf/template-single/internal/controller"
)

var (
	Main = gcmd.Command{
		Name:  "main",
		Usage: "main",
		Brief: "start http server",
		Func: func(ctx context.Context, parser *gcmd.Parser) (err error) {
			s := g.Server()
			s.Group("/", func(group *ghttp.RouterGroup) {
				group.Middleware(
					middleware.RequestReplayValidateMiddleware,
					middleware.RequestWrapMiddleware,
					middleware.RequestSignValidateMiddleware,
					middleware.ResponseWrapperMiddleware,
				)
				group.Bind(
					controller.Hello,
				)
			})
			s.Run()
			return nil
		},
	}
)
