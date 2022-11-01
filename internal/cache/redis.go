package cache

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"golang.org/x/sync/singleflight"

	"strconv"
	"time"
)

var (
	Cli           *redis.Client
	lockG         = &singleflight.Group{}
	ErrRedisEmpty = errors.New("redis client cannot be empty.")
)

func SetRedis() error {
	Cli = redis.NewClient(&redis.Options{
		Addr:         viper.GetString("redis.addr"),
		DB:           viper.GetInt("redis.db"),
		PoolSize:     viper.GetInt("redis.poolSize"),
		MinIdleConns: viper.GetInt("redis.idleConns"),
		Password:     viper.GetString("redis.password"),
	})

	_, err := Cli.Ping(context.Background()).Result()
	if err != nil {
		return err
	}

	return nil
}

/*
*
设置缓存
返回参数,,第一个数据,,第二个数据执行结果
*/
func CheckCache(key string, fn func() (interface{}, error), duration int64, needCache bool) (interface{}, error) {
	s, err := GetCache(key)
	if needCache && err == nil {
		return s, nil
	} else {
		var re interface{}
		//Num, ok := fn()
		//同一时间只有一个带相同key的函数执行 防击穿
		Num, ok, _ := lockG.Do(key, fn)
		if ok == nil {
			SetCache(key, Num, time.Duration(duration)*time.Second)
			re = Num
		} else {
			re = Num
		}

		return re, ok
	}

}

func SetCache(key string, data interface{}, duration time.Duration) error {

	if Cli == nil {
		return ErrRedisEmpty
	}
	dataMap := make(map[string]interface{})
	dataMap["data"] = data
	jsonData, err := json.Marshal(dataMap)
	if err != nil {
		return err
	}
	err = Cli.Set(context.Background(), key, jsonData, duration).Err()
	if err != nil {
		return err
	}
	return nil
}

func GetCache(key string) (interface{}, error) {

	if Cli == nil {
		return nil, ErrRedisEmpty
	}
	data, err := Cli.Get(context.Background(), key).Result()
	if err == nil && data != "" {
		dom := gjson.Parse(data)
		return dom.Get("data").Value(), err
	}
	if err == redis.Nil {
		return nil, nil
	}

	return "", err
}

func DelCache(key string) error {

	if Cli == nil {
		return ErrRedisEmpty
	}
	_ = Cli.Del(context.Background(), key).Err()

	return nil
}

// MatchPrefixCacheDel 按照前缀匹配key 并删除
func MatchPrefixCacheDel(k string) (err error) {
	keys, err := MatchPrefixCache(k)
	if err != nil {
		return
	}
	if len(keys) > 0 {
		for _, v := range keys {
			Cli.Del(context.Background(), v).Err()
		}
	}
	return nil
}

// MatchPrefixCache 按照前缀匹配key
func MatchPrefixCache(k string) (keys []string, err error) {
	qu := false
	cu := uint64(0)
	for !qu {
		list := []string{}
		list, cu, err = Cli.Scan(context.Background(), cu, k, 100).Result()
		if cu == 0 {
			qu = true
		}
		if len(list) > 0 {
			keys = append(keys, list...)
		}
	}
	return keys, err
}

// SetNx 加锁key 值为1
func SetNx(key string, t time.Duration) (res bool, err error) {

	ctx := context.Background()
	res, err = Cli.SetNX(ctx, key, 1, t).Result()
	return
}

// Incr key 值+1
func Incr(key string, t time.Duration) (res int64, err error) {

	ctx := context.Background()

	pipe := Cli.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, t)

	// Execute
	//
	//     MULTI
	//     INCR pipeline_counter
	//     EXPIRE pipeline_counts 3600
	//     EXEC
	//
	// using one rdb-server roundtrip.
	_, err = pipe.Exec(ctx)
	//fmt.Println(incr.Val(), err)
	res = incr.Val()
	return
}

// GetInt 获取key的int值
func GetInt(key string) (res int, err error) {

	ctx := context.Background()
	var result string
	result, err = Cli.Get(ctx, key).Result()
	if err == redis.Nil {
		res, err = 0, nil
	} else {
		res, _ = strconv.Atoi(result)
	}

	return
}

/*
*
md5
*/
func Md5Str(str string) string {
	data := []byte(str)
	has := md5.Sum(data)
	md5str := fmt.Sprintf("%x", has)
	return md5str
}

// 获取key的有效时间
func GetTtl(key string) (res time.Duration, err error) {

	ctx := context.Background()
	res, err = Cli.TTL(ctx, key).Result()
	if err == redis.Nil {
		res, err = 0, nil
	}

	return res, nil
}
