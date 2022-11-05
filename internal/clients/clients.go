package clients

import (
	"github.com/1uLang/libnet/utils/maps"
	"github.com/1uLang/zero-trust-gateway/internal/cache"
	"github.com/spf13/viper"
	"time"
)

// 客户端汇总

// Add 新增客户端认证信息 30秒到期
func Add(m maps.Map) error {

	err := cache.SetCache(cache.ClientAuthorityInfo+m.GetString("uuid"), m,
		time.Duration(viper.GetInt("timeout.authority")))
	if err != nil {
		return err
	}
	return nil
}

// Get 获取客户端认证信息
func Get(uuid string) (maps.Map, error) {
	info, err := cache.GetCache(cache.ClientAuthorityInfo + uuid)
	if info != nil {
		return info.(maps.Map), err
	}
	return nil, err
}

// Renew 客户端认证成功/续租 ttl
func Renew(uuid string) error {

	err := cache.SetCache(cache.ClientAuthorityInfo+uuid, uuid,
		time.Duration(viper.GetInt("timeout.spa")))
	if err != nil {
		return err
	}
	return nil
}
