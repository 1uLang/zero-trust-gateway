package sdp

import (
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/message"
	"github.com/1uLang/libnet/utils/maps"
	"github.com/1uLang/zero-trust-gateway/internal/clients"
	message2 "github.com/1uLang/zero-trust-gateway/internal/message"
	"github.com/1uLang/zero-trust-gateway/internal/wireguard"
	"github.com/1uLang/zero-trust-gateway/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"time"
)

type handler struct {
}
type conn struct {
	c      *libnet.Connection
	ticker *time.Ticker
}

func (this handler) OnConnect(c *libnet.Connection) {
	log.Info("[SDP Client] connect control success")
	// 注册 - 网关上线
	//todo：加入注册失败机制
	con := &conn{c: c}
	if err := con.login(c, maps.Map{"type": connection_gateway}); err != nil {
		log.Fatal("[SDP Client] login failed : ", err)
		c.Close(err.Error())
		return
	}
	// setup buffer
	clientBuffer := message.NewBuffer(message2.CheckHeader)
	clientBuffer.OptValidateId = true
	clientBuffer.OnMessage(func(msg message.MessageI) {
		con.onMessage((msg).(*message2.Message))
	})
	if err := c.SetBuffer(clientBuffer); err != nil {
		log.Fatal("[SDP Client] set message buffer failed : ", err)
		c.Close(err.Error())
		return
	}
}

func (this handler) OnMessage(c *libnet.Connection, bytes []byte) {
}

func (this handler) OnClose(c *libnet.Connection, reason string) {
	log.Error("[SDP Control] connection close : ", reason)
}

// 定时发送心跳包文
func (this conn) startKeepaliveTicker() {

	this.ticker = time.NewTicker(time.Duration(viper.GetInt("timeout.keepalive")) * time.Second)

	for range this.ticker.C {
		if !this.c.IsClose() {
			msg := message2.Message{Type: message2.KeepaliveRequestCode}
			this.c.Write(msg.Marshal())
		} else {
			return
		}
	}
}

// 处理消息
func (this *conn) onMessage(msg *message2.Message) {
	switch msg.Type {
	case message2.LoginResponseCode:
		this.handleLoginAckMessage(msg)
	case message2.IHOnlineRequestCode:
		this.handleIHOnlineMessage(msg)
	case message2.ServerProtectRequestCode:
		this.handleServerProtectMessage(msg)
	case message2.CustomRequestCode:
		this.handleCustomMessage(msg)
	}
}

// 登陆消息
func (this *conn) login(c *libnet.Connection, m maps.Map) error {

	reply := &message2.Message{
		Type: message2.LoginRequestCode,
		Data: m.AsJSON(),
	}
	_, err := c.Write(reply.Marshal())
	fmt.Println("==== send lopin message failed : ", err)
	return err
}

// AH/IH 处理登录响应
func (this *conn) handleLoginAckMessage(msg *message2.Message) {

	m, err := maps.DecodeJSON(msg.Data)
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
		this.c.Close("authority failed : " + m.GetString("message"))
		//无效的认证凭证
	case 2:
		//限制登录
		log.Warn("[SDP Client]login limit ", m.GetString("message"))
		this.c.Close("login limit " + m.GetString("message"))
	}
}

// AH 处理IH上线消息
func (this *conn) handleIHOnlineMessage(msg *message2.Message) {
	m, err := msg.DecodeData()
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
		reply := &message2.Message{
			Type: message2.IHOnlineResponseCode,
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
		if _, err = this.c.Write(reply.Marshal()); err != nil {
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
func (this *conn) handleServerProtectMessage(msg *message2.Message) {
	m, err := msg.DecodeData()
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
func (this *conn) handleCustomMessage(msg *message2.Message) {
	// todo：处理自定义消息
	log.Info("[SDP Client] custom message : ", msg.Data)
}
