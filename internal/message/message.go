package message

import (
	"encoding/binary"
	"encoding/json"
	"github.com/1uLang/zero-trust-gateway/utils/maps"
)

const (
	MessageHeaderLength = 5
	MessageLengthIndex  = 2

	LoginRequestCode         = 0x00 //ah/ih ----> control 登录消息
	LoginResponseCode        = 0x01 //control ----> ah/ih 登录响应消息
	AHLogoutRequestCode      = 0x02 // ah ----> control 注销消息
	KeepaliveRequestCode     = 0x03 // ah <----> control 心跳消息
	ServerProtectRequestCode = 0x04 // control ----> ah ah保护服务消息
	IHOnlineRequestCode      = 0x05 // control ----> ah ih认证消息
	AHListRequestCode        = 0x06 // control ----> ih ah信息列表
	IHLogoutRequestCode      = 0x07 // ih ----> control 注销请求消息
	IHOnlineResponseCode     = 0x08 // ah ----> control ih上线后ah业务相关数据信息体响应消息
	CustomRequestCode        = 0xff // 自定义消息
)

// Message tls 通讯消息体
// Code：
// 0x00 AH 登录信息包  AH ----> 控制器
// 0x01 控制器 AH登录响应包  控制器 ------> AH
// 0x02 AH 登出响应包 AH  --------> 控制器
// 0x03 AH/控制器 keepalive 心跳包
// 0x04 AH AH服务信息包
type Message struct {
	Code   uint8  `json:"code"`   // 消息类型  0x00 0x01 0x02
	Length uint32 `json:"length"` // 消息体长度
	Data   []byte `json:"data"`   // 消息体
}

// 解析选项
// 选项格式：[4字节选项内容长度] [ 选项内容 ] [数据]
func (this *Message) DecodeOptions() (maps.Map, error) {
	if len(this.Data) < 4 {
		return nil, nil
	}

	length := binary.BigEndian.Uint32(this.Data[:4])
	if length == 0 {
		return nil, nil
	}

	data := this.Data[4 : 4+length]
	options := maps.Map{}
	err := json.Unmarshal(data, &options)

	this.Data = this.Data[4+length:]

	return options, err
}

// 编码消息
func (this *Message) Marshal() []byte {
	result := []byte{this.Code}
	// ID
	buf := make([]byte, 4)
	// Length
	this.Length = uint32(len(this.Data))
	binary.BigEndian.PutUint32(buf, this.Length)
	result = append(result, buf[:4]...)

	// Data
	result = append(result, this.Data...)
	return result
}
