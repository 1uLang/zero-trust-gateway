package main

import (
	"flag"
	"github.com/1uLang/zero-trust-gateway/internal/cache"
	"github.com/1uLang/zero-trust-gateway/internal/config"
	"github.com/1uLang/zero-trust-gateway/internal/logs"
	"github.com/1uLang/zero-trust-gateway/internal/sdp"
	"github.com/1uLang/zero-trust-gateway/internal/spa"
	"github.com/1uLang/zero-trust-gateway/internal/wireguard"
	_ "github.com/1uLang/zero-trust-gateway/utils/path"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

var (
	cfgFile = flag.String("c", "./config/config.yaml", "set config file")
)

func main() {
	// 参数解析
	flag.Parse()
	// 初始化配置文件
	config.Init(*cfgFile)
	// 初始化log
	logs.Init()
	// 初始化redis
	if err := cache.SetRedis(); err != nil {
		log.Fatal("init redis failed : ", err)
		return
	}
	// 初始化wireguard
	if err := wireguard.Init(); err != nil {
		log.Fatal("init vpn gateway : ", err)
		return
	}
	connect := 0
	spaCount := 0
	var err error
AUTHORITY:
	// 1. 向控制器发送spa 认证
	err = spa.RunClient()
	if err != nil {
		panic(err)
	}
	spaCount++
CONNECT:
	connect++
	// 2. 连接控制器
	err = sdp.RunClient()
	if err != nil {
		// 连接拒绝 可能是 spa认证还未生效
		if strings.Contains(err.Error(), "connection refused") && connect <= 5 {
			time.Sleep(10 * time.Millisecond)
			goto CONNECT
		}
		// 连接拒绝 可能是 spa认证失败 重试
		if spaCount <= 3 {
			time.Sleep(10 * time.Millisecond)
			goto AUTHORITY
		}
		panic(err)
	}

	//3. 启动spa服务器 等待客户端认证
	err = spa.RunServe()
	if err != nil {
		panic(err)
	}
}
