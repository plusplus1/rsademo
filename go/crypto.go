package libs

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"runtime"
)

const (
	deParallelSize = 1024 * 20
)

type (
	onePart struct {
		Index int
		Data  []byte
	}

	signHashOpts struct{}
)

func calcDecryptSize(sk *rsa.PrivateKey) int {
	return sk.N.BitLen() / 8
}

func calcEncryptSize(pk *rsa.PublicKey) int {
	return pk.N.BitLen()/8 - 28
}

func (so signHashOpts) HashFunc() crypto.Hash {
	return crypto.SHA1
}

func Encrypt(text string, pk *rsa.PublicKey) (string, error) {
	bufIn := bytes.NewBufferString(text)
	bufOut := bytes.NewBuffer(nil)

	var enSize = calcEncryptSize(pk)

	buf := make([]byte, enSize)

	for {
		if n, errReadBuf := bufIn.Read(buf); errReadBuf == nil && n > 0 {
			if bs, errEncrypt := rsa.EncryptPKCS1v15(rand.Reader, pk, buf[0:n]); errEncrypt != nil {
				return "", errEncrypt
			} else {
				if _, errWriteBuf := bufOut.Write(bs); errWriteBuf != nil {
					return "", errWriteBuf
				}
			}
		} else {
			break
		}
	}

	return base64.StdEncoding.EncodeToString(bufOut.Bytes()), nil
}

func Decrypt(text string, sk *rsa.PrivateKey, autoMultiProcess bool) (string, error) {
	if buf, err := base64.StdEncoding.DecodeString(text); err == nil {
		bufIn := bytes.NewBuffer(buf)
		if autoMultiProcess && bufIn.Len() > deParallelSize {
			if bs, err := decryptParallel(bufIn, sk); err != nil {
				return "", err
			} else {
				return string(bs), nil
			}
		}
		if bs, err := decryptOneProcess(bufIn, sk); err != nil {
			return "", err
		} else {
			return string(bs), nil
		}
	} else {
		return "", err
	}
}

func DecryptNoneBase64(cipher []byte, sk *rsa.PrivateKey, autoParallel bool) ([]byte, error) {
	bufIn := bytes.NewBuffer(cipher)
	if autoParallel && bufIn.Len() > deParallelSize {
		return decryptParallel(bufIn, sk)
	}
	return decryptOneProcess(bufIn, sk)
}

func decryptOneProcess(bufIn *bytes.Buffer, sk *rsa.PrivateKey) ([]byte, error) {

	var deSize = calcDecryptSize(sk)

	var buf = make([]byte, deSize)
	var bufOut = bytes.NewBuffer(nil)

	for {
		if n, errReadBuf := bufIn.Read(buf); errReadBuf == nil && n > 0 {
			if bs, errDecrypt := rsa.DecryptPKCS1v15(rand.Reader, sk, buf[0:n]); errDecrypt != nil {
				return nil, errDecrypt
			} else {
				if _, errWriteBuf := bufOut.Write(bs); errWriteBuf != nil {
					return nil, errWriteBuf
				}
			}
		} else {
			break
		}
	}

	return bufOut.Bytes(), nil
}

func decryptParallel(bufIn *bytes.Buffer, sk *rsa.PrivateKey) ([]byte, error) {

	inSize := bufIn.Len()

	var deSize = calcDecryptSize(sk)

	var totalCount = (inSize + deSize - 1) / deSize
	var finishedCount = 0

	var taskChan = make(chan *onePart, runtime.NumCPU()-1)
	var doneChan = make(chan error, 1)

	var outParts = make([][]byte, totalCount)

	decryptOnePart := func(in *onePart) {
		bs, err := rsa.DecryptPKCS1v15(rand.Reader, sk, in.Data)
		if err == nil {
			outParts[in.Index] = bs
		}
		doneChan <- err
	}

	go func() {
		for {
			t := <-taskChan
			go decryptOnePart(t)
		}

	}()

	go func() {
		for i := 0; i < totalCount; i++ {
			var buf = make([]byte, deSize)
			n, _ := bufIn.Read(buf)
			one := &onePart{Index: i, Data: buf[0:n]}
			taskChan <- one
		}
	}()

	for {
		select {

		case err := <-doneChan:
			finishedCount++
			if err != nil {
				return nil, err
			}
		}

		if finishedCount >= totalCount {
			break
		}
	}

	return bytes.Join(outParts, nil), nil
}

func Sign(text string, sk *rsa.PrivateKey) (string, error) {

	h := signHashOpts{}.HashFunc()
	hObj := h.New()
	hObj.Write([]byte(text))
	hashed := hObj.Sum(nil)

	if bs, err := rsa.SignPKCS1v15(rand.Reader, sk, h, hashed); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(bs), nil
	}

}

func Verify(text string, sig string, pk *rsa.PublicKey) bool {

	if sigBytes, err := base64.StdEncoding.DecodeString(sig); err == nil {

		h := signHashOpts{}.HashFunc()
		hObj := h.New()
		hObj.Write([]byte(text))
		hashed := hObj.Sum(nil)

		if err = rsa.VerifyPKCS1v15(pk, h, hashed, sigBytes); err == nil {
			return true
		}
	}
	return false
}
