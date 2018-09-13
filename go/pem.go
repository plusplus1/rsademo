package libs

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func DecodePem(key string) (*pem.Block, error) {
	return DecodePemBytes([]byte(key))
}

func DecodePemBytes(key []byte) (block *pem.Block, err error) {
	if p, _ := pem.Decode(key); p != nil {
		return p, nil
	} else {
		return nil, errors.New("decode pem fail")
	}
}

func LoadPubKeyBytes(key []byte) (pk *rsa.PublicKey, err error) {
	var k interface{}
	if k, err = x509.ParsePKIXPublicKey(key); err == nil {
		if pk, ok := k.(*rsa.PublicKey); ok {
			return pk, nil
		}
	}
	if err == nil {
		err = errors.New("LoadPubKeyBytes fail")
	}
	return
}

func LoadPemPubKeyBytes(key []byte) (pk *rsa.PublicKey, err error) {

	var block *pem.Block
	if block, err = DecodePemBytes(key); err == nil {
		return LoadPubKeyBytes(block.Bytes)
	}
	return

}

func LoadPKCSPriKeyBytes(key []byte) (sk *rsa.PrivateKey, err error) {

	if sk, err = x509.ParsePKCS1PrivateKey(key); err != nil {
		var tmp interface{}
		if tmp, err = x509.ParsePKCS8PrivateKey(key); err == nil {
			sk = tmp.(*rsa.PrivateKey)
		}
	}
	if err != nil {
		return nil, err
	}
	if sk == nil {
		err = errors.New("LoadPKCSPriKeyBytes fail")
	}
	return
}

func LoadPemPKCSPriKeyBytes(key []byte) (sk *rsa.PrivateKey, err error) {
	var block *pem.Block
	if block, err = DecodePemBytes(key); err != nil {
		return
	}
	return LoadPKCSPriKeyBytes(block.Bytes)

}

func LoadPemPubKey(key string) (pk *rsa.PublicKey, err error) {
	return LoadPemPubKeyBytes([]byte(key))
}
func LoadPemPKCSPriKey(key string) (sk *rsa.PrivateKey, err error) {
	return LoadPemPKCSPriKeyBytes([]byte(key))
}
