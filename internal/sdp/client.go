package sdp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/connection"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/zero-trust-gateway/internal/clients"
	"github.com/1uLang/zero-trust-gateway/internal/message"
	"github.com/1uLang/zero-trust-gateway/utils/maps"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"time"
)

type client struct {
	isClosed     bool
	conn         *libnet.Client
	clientBuffer *message.Buffer
	ticker       *time.Ticker
}

var clt = client{isClosed: false}

// 定时发送心跳包文
func (this client) startKeepaliveTicker() {

	this.ticker = time.NewTicker(time.Duration(viper.GetInt("timeout.keepalive")) * time.Second)

	for range this.ticker.C {
		if !this.isClosed {
			msg := message.Message{Code: message.KeepaliveRequestCode}
			this.conn.Write(msg.Marshal())
		} else {
			return
		}
	}
}

// 处理消息
func (this *client) onMessage(msg *message.Message) {
	switch msg.Code {
	case message.LoginResponseCode:
		this.handleLoginAckMessage(msg)
	case message.IHOnlineRequestCode:
		this.handleIHOnlineMessage(msg)
	case message.ServerProtectRequestCode:
		this.handleServerProtectMessage(msg)
	case message.CustomRequestCode:
		this.handleCustomMessage(msg)
	}
}

// 登陆消息
func (this *client) login(m maps.Map) error {

	reply := &message.Message{
		Code: message.LoginRequestCode,
		Data: m.AsJSON(),
	}
	_, err := this.conn.Write(reply.Marshal())
	return err
}

// AH/IH 处理登录响应
func (this *client) handleLoginAckMessage(msg *message.Message) {
	m := maps.Map{}
	err := json.Unmarshal(msg.Data, &m)
	if err != nil {
		return
	}
	switch m.GetInt8("code") {
	case 0: //登录成功 - 定时发送心跳
		// 开启定时任务 发送心跳报
		go this.startKeepaliveTicker()
		return
	case 1: //记录错误信息：
		log.Error("[SDP Client]authorize failed ", m.GetString("message"))
		//无效的认证凭证
	case 2:
		//限制登录
		log.Warn("[SDP Client]login limit ", m.GetString("message"))
	}
}

// AH 处理IH上线消息
func (this *client) handleIHOnlineMessage(msg *message.Message) {
	m, err := msg.DecodeOptions()
	if err != nil {
		log.Error("[SDP Client]decode ih online message error:", err)
		return
	}
	// 保存 ih 信息 等待ih来spa敲门
	// todo：将生成好的wireguard配置文件/sdp 客户端连网关相关信息返回给控制器
	if err = clients.Add(m); err != nil {
		log.Error("[SDP Client] client online save info error:", err)
	}
}

// AH 处理ah保护服务消息
func (this *client) handleServerProtectMessage(msg *message.Message) {
	m, err := msg.DecodeOptions()
	if err != nil {
		log.Warn("[SDP Client]decode ah server proto message error:", err)
		return
	}
	fmt.Println("server proto :", m)
	//todo:把源站IP等信息写入到wireguard 需要拦截的IP列表中
}

// ah/ih 自定义消息（错误消息）
func (this *client) handleCustomMessage(msg *message.Message) {
	// todo：处理自定义消息
	log.Info("[SDP Client] custom message : ", msg.Data)
}

func (this client) OnConnect(c *connection.Connection) {
	log.Info("[SDP Client] connect control success")
	// 注册 - 网关上线
	//todo：加入注册失败机制
	if err := this.login(maps.Map{}); err != nil {
		log.Fatal("[SDP Client] login failed : ", err)
		this.isClosed = true
		this.conn.Close()
		return
	}
}

func (this client) OnMessage(c *connection.Connection, bytes []byte) {

	// setup buffer
	this.clientBuffer = message.NewBuffer()
	this.clientBuffer.OptValidateId = true
	this.clientBuffer.OnMessage(this.onMessage)
	if len(bytes) > 0 {
		this.clientBuffer.Write(bytes)
	}
}

func (this client) OnClose(c *connection.Connection, err error) {
	this.isClosed = true
	log.Error("[SDP Control] connection close : ", err)
}

// RunClient 连接控制器
func RunClient() error {
	addr := fmt.Sprintf("%s:%d", viper.GetString("control.addr"), viper.GetInt("control.sdp.port"))
	cert, err := os.ReadFile("./certs/ca.crt")
	if err != nil {
		log.Fatalf("could not open certificate file: %v", err)
		return err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(cert)

	certificate, err := tls.LoadX509KeyPair("./certs/client.crt", "./certs/client.key")
	if err != nil {
		log.Fatalf("could not load certificate: %v", err)
		return err
	}

	// Create a tls client and supply the created CA pool and certificate
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{certificate},
	}
	clt.conn, err = libnet.NewClient(addr, clt,
		options.WithTimeout(time.Duration(viper.GetInt("timeout.connect"))))

	return clt.conn.DialTLS(tlsConfig)
}
