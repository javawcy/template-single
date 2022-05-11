package cecrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
)

type cRsa struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func newCERsa(pubKey, priKey []byte) (*cRsa, error) {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return nil, gerror.WrapCode(gcode.CodeInvalidParameter, errors.New("decode failed"), `cRsa pubKey decode failed`)
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)

	block, _ = pem.Decode(priKey)
	if block == nil {
		return nil, gerror.WrapCode(gcode.CodeInvalidParameter, err, `cRsa priKey decode failed`)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pri, ok := priv.(*rsa.PrivateKey)
	if ok {
		return &cRsa{
			publicKey:  pub,
			privateKey: pri,
		}, nil
	}
	return nil, gerror.WrapCode(gcode.CodeInvalidParameter, err, `cRsa init failed`)
}

//PublicEncrypt 公钥加密
func (r *cRsa) publicEncrypt(data string) (string, error) {
	partLen := r.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bytes, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(bytes)
	}

	return hex.EncodeToString(buffer.Bytes()), nil
}

//PrivateDecrypt 私钥解密
func (r *cRsa) privateDecrypt(encrypted string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8
	raw, err := hex.DecodeString(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}
