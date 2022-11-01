package spa

import (
	"errors"
	"github.com/1uLang/libspa"
	libspaclt "github.com/1uLang/libspa/client"
	"github.com/1uLang/zero-trust-gateway/utils"
	"github.com/spf13/viper"
	"net"
)

// RunClient 向控制器发送spa包 打开与控制器的认证端口
func RunClient() error {
	// 读取配置文件 获取 控制器相关spa服务信息 addr protocol encry secret key
	clt := libspaclt.New()
	clt.Port = viper.GetInt("control.spa.port")
	clt.Addr = viper.GetString("control.addr")
	clt.Protocol = viper.GetString("control.spa.protocol")
	clt.Method = viper.GetString("control.spa.method")
	clt.KEY = viper.GetString("control.spa.key")
	clt.IV = viper.GetString("control.spa.iv")
	clt.Test = viper.GetBool("debug")
	cip, err := utils.GetExternalIP()
	if err != nil {
		return errors.New("获取本地IP失败：" + err.Error())
	}
	deviceId, err := utils.GetDeviceId()
	if err != nil {
		return errors.New("获取设备ID失败：" + err.Error())
	}
	return clt.Send(&libspa.Body{
		ClientDeviceId: deviceId,
		ClientPublicIP: cip,
		ServerPublicIP: net.ParseIP(clt.Addr),
	})
}
