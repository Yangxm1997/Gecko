package coder

import (
	"errors"
	"github.com/yangxm/gecko/entity"
)

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
