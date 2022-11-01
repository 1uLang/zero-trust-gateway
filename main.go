package main

import (
	"flag"
	"github.com/1uLang/zero-trust-gateway/internal/cache"
	"github.com/1uLang/zero-trust-gateway/internal/sdp"
	"github.com/1uLang/zero-trust-gateway/internal/spa"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultConfigFile = "config.yaml"

var (
	cfgFile = flag.String("c", "config.yaml", "set config file")
)

func main() {
	// 参数解析
	flag.Parse()
	// 初始化配置文件
	initConfig()
	// 初始化log
	initLog()
	// 初始化redis
	if err := cache.SetRedis(); err != nil {
		log.Fatal("init redis failed : ", err)
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

	// 3. 启动spa服务器 等待客户端认证
	spa.RunServe()
}

// Read config values
func initConfig() {
	if *cfgFile != "" {
		// Use config file path provided by the flag
		viper.SetConfigFile(*cfgFile)
	} else {
		// User default config file located inside the same dir as the executable
		exePath, err := os.Executable()
		if err != nil {
			panic(err)
		}

		viper.AddConfigPath(filepath.Dir(exePath))
		viper.SetConfigFile(defaultConfigFile)
	}

	if err := viper.ReadInConfig(); err != nil {
		log.Error("failed to read config")
		log.Error(err)
		os.Exit(-1)
	}
}

func initLog() {

	if viper.GetBool("debug") {
		log.SetLevel(log.DebugLevel)
	}
}
