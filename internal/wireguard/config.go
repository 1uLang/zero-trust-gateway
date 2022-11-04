package wireguard

import (
	"errors"
	"github.com/1uLang/zero-trust-gateway/utils"
	"github.com/1uLang/zero-trust-gateway/utils/path"
	"github.com/mitchellh/go-homedir"
	"os"
	"strings"
	"sync"
)

var clientConfigTemplate = "[Interface]\nPrivateKey = [PRIVATE]\nAddress = 10.10.10.2\nDNS = 8.8.8.8\n\n[Peer]\nPublicKey = [PUBLIC]\nEndpoint = [PUBLICIP]:54321\nAllowedIPs = 10.10.10.2/32[IPS]"
var locker = sync.RWMutex{}
var clientConfig = ""
var publicIp = ""
var privateKey = ""
var publicKey = ""
var homeDir = ""

// 受保护的服务IP列表
var protectServers = []string{}

// GetConfig 获取客户端的配置文件
func GetConfig() (cfg string, err error) {
	locker.RLocker()
	if clientConfig == "" {
		locker.RUnlock()
		return syncClientCfg()
	} else {
		cfg = clientConfig
		locker.RUnlock()
		return "", nil
	}
}

func SetProtectedServer(ips []interface{}) error {
	protectServers = []string{}
	for _, ip := range ips {
		protectServers = append(protectServers, ip.(string))
	}
	_, err := syncClientCfg()
	return err
}
func syncClientCfg() (string, error) {
	if publicIp == "" || publicKey == "" || privateKey == "" {
		return "", errors.New("请先初始化网关")
	}
	locker.Lock()
	clientConfig = strings.Replace(clientConfigTemplate, "[PRIVATE]", privateKey, 1)
	clientConfig = strings.Replace(clientConfig, "[PUBLIC]", publicKey, 1)
	clientConfig = strings.Replace(clientConfig, "[PUBLICIP]", publicIp, 1)
	allowIps := ""
	if len(protectServers) > 0 {
		allowIps = ","
		allowIps += strings.Join(protectServers, ",")
	}
	clientConfig = strings.Replace(clientConfig, "[IPS]", allowIps, 1)
	locker.Unlock()
	return clientConfig, nil
}

// Init 初始化 获取 公网IP 生成wireguard公钥
func Init() error {
	// 获取公网IP
	ip, err := utils.GetExternalIP()
	if err != nil {
		return err
	}
	publicIp = ip.String()

	_ = os.Chmod(path.BinDir()+"/startwg.sh", 777)
	// 启动 wireguard
	_, err = utils.RunCMD(path.BinDir() + "/startwg.sh")

	homeDir, err = homedir.Dir()
	// 获取wireguard 密钥 pri2  pub1
	pub1, err := os.ReadFile(homeDir + "/.wireguard/pub1")
	if err != nil {
		return err
	}
	pri2, err := os.ReadFile(homeDir + "/.wireguard/pri2")
	if err != nil {
		return err
	}
	publicKey = string(pub1)
	privateKey = string(pri2)
	return nil
}
