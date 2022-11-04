package spa

import (
	"errors"
	"github.com/1uLang/libspa"
	libspaclt "github.com/1uLang/libspa/client"
	"github.com/1uLang/zero-trust-gateway/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"net"
	"time"
)

var clt = struct {
	*libspaclt.Client
	deviceId string
	publicIp net.IP
}{
	Client: libspaclt.New(),
}
var isClosed bool

// RunClient 向控制器发送spa包 打开与控制器的认证端口
func RunClient() (err error) {
	// 读取配置文件 获取 控制器相关spa服务信息 addr protocol encry secret key

	clt.Port = viper.GetInt("control.spa.port")
	clt.Addr = viper.GetString("control.addr")
	clt.Protocol = viper.GetString("control.spa.protocol")
	clt.Method = viper.GetString("control.spa.method")
	clt.KEY = viper.GetString("control.spa.key")
	clt.IV = viper.GetString("control.spa.iv")
	clt.Test = viper.GetBool("debug")
	clt.publicIp, err = utils.GetExternalIP()
	if err != nil {
		return errors.New("获取本地IP失败：" + err.Error())
	}
	clt.deviceId, err = utils.GetDeviceId()
	if err != nil {
		return errors.New("获取设备ID失败：" + err.Error())
	}
	go ticker()
	return loop()
}

func ticker() {
	ticker := time.NewTicker(time.Duration(viper.GetInt("timeout.spa")/2) * time.Second)

	for range ticker.C {
		if !isClosed {
			if err := loop(); err != nil {
				log.Warn("[SPA Control] loop send spa error ", err)
			}
		} else {
			return
		}
	}
}
func loop() error {
	return clt.Send(&libspa.Body{
		ClientDeviceId: clt.deviceId,
		ClientPublicIP: clt.publicIp,
		ServerPublicIP: net.ParseIP(clt.Addr),
	})
}
