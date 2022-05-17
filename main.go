package main

import (
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/os/genv"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/gogf/template-single/internal/cmd"
)

func main() {
	ctx := gctx.New()
	err := genv.Set("GF_GCFG_FILE", "config.dev.yaml")
	if err != nil {
		glog.Error(ctx, "config failed")
	}
	cmd.Main.Run(ctx)
}
