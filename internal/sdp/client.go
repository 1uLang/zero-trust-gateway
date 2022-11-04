package sdp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/zero-trust-gateway/internal/clients"
	"github.com/1uLang/zero-trust-gateway/internal/message"
	"github.com/1uLang/zero-trust-gateway/internal/wireguard"
	"github.com/1uLang/zero-trust-gateway/utils"
	"github.com/1uLang/zero-trust-gateway/utils/maps"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"time"
)

const (
	connection_type = iota
	connection_client
	connection_gateway
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
func (this *client) login(c *libnet.Connection, m maps.Map) error {

	reply := &message.Message{
		Code: message.LoginRequestCode,
		Data: m.AsJSON(),
	}
	_, err := c.Write(reply.Marshal())
	fmt.Println("==== send lopin message failed : ", err)
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
	this.isClosed = true
	this.conn.Close()
}

// AH 处理IH上线消息
func (this *client) handleIHOnlineMessage(msg *message.Message) {
	m, err := msg.DecodeOptions()
	if err != nil {
		log.Error("[SDP Client]decode ih online message error:", err)
		return
	}
	// 保存 ih 信息 等待ih来spa敲门
	if err = clients.Add(m); err != nil {
		log.Error("[SDP Client] client online save info error:", err)
	} else { // 记录成功 封装网关信息 响应控制器 并由控制器下发给客户端
		cfg, err := wireguard.GetConfig()
		if err != nil {
			log.Error("[SDP Client] get wireguard client config error:", err)
			return
		}
		eip, err := utils.GetExternalIP()
		if err != nil {
			log.Error("[SDP Client] get public ip error:", err)
			return
		}
		reply := &message.Message{
			Code: message.IHOnlineResponseCode,
			Data: maps.Map{
				"addr":      eip,
				"port":      viper.GetString("spa.port"),
				"method":    viper.GetString("spa.method"),
				"key":       viper.GetString("spa.key"),
				"iv":        viper.GetString("spa.iv"),
				"clientCfg": cfg,
			}.AsJSON(),
		}
		retry := 0
	WRITE:
		if _, err = this.conn.Write(reply.Marshal()); err != nil {
			log.Error("[SDP Client] send ih online response error:", err)
			if retry < 5 {
				retry++
				log.Errorf("[SDP Client] %d try to send", retry)
				goto WRITE
			}
		}
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
	if err := wireguard.SetProtectedServer(m.GetSlice("ips")); err != nil {
		log.Warn("[SDP Client]set gateway protected server error:", err)
		return
	}
}

// ah/ih 自定义消息（错误消息）
func (this *client) handleCustomMessage(msg *message.Message) {
	// todo：处理自定义消息
	log.Info("[SDP Client] custom message : ", msg.Data)
}

func (this client) OnConnect(c *libnet.Connection) {
	log.Info("[SDP Client] connect control success")
	// 注册 - 网关上线
	//todo：加入注册失败机制
	if err := this.login(c, maps.Map{"type": connection_gateway}); err != nil {
		log.Fatal("[SDP Client] login failed : ", err)
		this.isClosed = true
		c.Close(err.Error())
		return
	}
}

func (this client) OnMessage(c *libnet.Connection, bytes []byte) {

	// setup buffer
	this.clientBuffer = message.NewBuffer()
	this.clientBuffer.OptValidateId = true
	this.clientBuffer.OnMessage(this.onMessage)
	if len(bytes) > 0 {
		this.clientBuffer.Write(bytes)
	}
}

func (this client) OnClose(c *libnet.Connection, reason string) {
	this.isClosed = true
	log.Error("[SDP Control] connection close : ", reason)
}

// RunClient 连接控制器
func RunClient() error {
	addr := fmt.Sprintf("%s:%d", viper.GetString("control.addr"), viper.GetInt("control.sdp.port"))
	cert, err := os.ReadFile(viper.GetString("control.sdp.ca"))
	if err != nil {
		log.Fatalf("could not open certificate file: %v", err)
		return err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(cert)

	certificate, err := tls.LoadX509KeyPair(viper.GetString("control.sdp.cert"), viper.GetString("control.sdp.key"))
	if err != nil {
		log.Fatalf("could not load certificate: %v", err)
		return err
	}

	// Create a tls client and supply the created CA pool and certificate
	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		ClientCAs:          caCertPool,
		Certificates:       []tls.Certificate{certificate},
		ClientAuth:         tls.RequireAndVerifyClientCert,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	clt.conn, err = libnet.NewClient(addr, clt,
		options.WithTimeout(time.Duration(viper.GetInt("timeout.connect"))))

	return clt.conn.DialTLS(tlsConfig)
}
