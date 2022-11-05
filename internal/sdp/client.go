package sdp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/message"
	"github.com/1uLang/libnet/options"
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
	clt.conn, err = libnet.NewClient(addr, new(handler),
		options.WithTimeout(time.Duration(viper.GetInt("timeout.connect"))))

	return clt.conn.DialTLS(tlsConfig)
}
