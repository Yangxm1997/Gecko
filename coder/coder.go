package coder

import (
	"errors"
	"github.com/yangxm/gecko/entity"
	"google.golang.org/protobuf/proto"
)

func Encode(_type, flag byte, clientID, connId string, serverType byte, data []byte) ([]byte, error) {
	if data == nil {
		return nil, errors.New("data is nil")
	}

	header := &entity.MessageHeader{
		Type:       []byte{_type},
		Flag:       []byte{flag},
		ClientID:   clientID,
		ConnID:     connId,
		ServerType: []byte{serverType},
	}

	// TODO:
	var tvs []*entity.MessageTV
	var encodedData []byte = data

	message := &entity.Message{
		Header: header,
		Tvs:    tvs,
		Data:   encodedData,
	}

	return proto.Marshal(message)
}

func Decode(message *entity.Message) ([]byte, error) {
	if message == nil {
		return nil, errors.New("message is nil")
	}

	if message.Data == nil {
		return nil, errors.New("message data is nil")
	}
	// TODO: decode message data
	return message.Data, nil
}
