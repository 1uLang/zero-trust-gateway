package spa

import (
	"errors"
	"github.com/1uLang/libnet/connection"
	"github.com/1uLang/libnet/encrypt"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/libspa"
	libspasrv "github.com/1uLang/libspa/server"
	"github.com/1uLang/zero-trust-gateway/internal/clients"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"time"
)

type server struct {
}

func (s server) OnConnect(conn *connection.Connection) {

}

func (s server) OnAuthority(body *libspa.Body, err error) (*libspasrv.Allow, error) {

	clt, err := clients.Get(body.ClientDeviceId)
	if err != nil {
		log.Warn("[SPA Server] get client authority info error : ", err)
		return nil, err
	}
	if clt == nil {
		return nil, nil
	}
	// todo : 对客户端设备及身份进行验证
	// todo: 认证结果 写入到日志数据库中
	return &libspasrv.Allow{TcpPorts: viper.GetIntSlice("spa.allow.tcpPort"), UdpPorts: viper.GetIntSlice("spa.allow.udpPort")}, nil
}

func (s server) OnClose(conn *connection.Connection, err error) {
}

var srv = server{}

func RunServe() error {
	spaSrv := libspasrv.New()
	spaSrv.Port = viper.GetInt("control.spa.port")
	spaSrv.Protocol = viper.GetString("control.spa.protocol")
	spaSrv.Test = viper.GetBool("debug")
	spaSrv.Timeout = viper.GetInt("debug")
	method, err := encrypt.NewMethod(viper.GetString(""))
	if err != nil {
		return errors.New("获取本地IP失败：" + err.Error())
	}
	return spaSrv.Run(srv,
		options.WithEncryptMethod(method),
		options.WithEncryptMethodPublicKey([]byte(viper.GetString(""))),
		options.WithEncryptMethodPrivateKey([]byte(viper.GetString(""))),
		options.WithTimeout(5*time.Second))
}
