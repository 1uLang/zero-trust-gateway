package sdp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/message"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/libnet/utils/maps"
	message2 "github.com/1uLang/zero-trust-gateway/internal/message"
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
	conn *libnet.Client
}

var clt = client{}

func (this client) OnConnect(c *libnet.Connection) {
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

func (this client) OnMessage(c *libnet.Connection, bytes []byte) {
}

func (this client) OnClose(c *libnet.Connection, reason string) {
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
