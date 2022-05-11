package cecrypto

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/forgoer/openssl"
	"github.com/gogf/gf/v2/crypto/gmd5"
	"github.com/gogf/gf/v2/crypto/gsha1"
	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/text/gstr"
)

//DecodeC decode c
func DecodeC(content string, time int64, pub string, pri string) (string, error) {
	c, k := splitContentAndKey(content)
	xRsa, err := newCERsa([]byte(pub), []byte(pri))
	if err != nil {
		panic(err)
	}
	aesKey, err := xRsa.privateDecrypt(k)
	iv := createAESIVWithKey(aesKey)
	cBytes, _ := hex.DecodeString(c)
	dst, err := openssl.AesCBCDecrypt(cBytes, []byte(aesKey), []byte(iv), openssl.PKCS7_PADDING)
	if err != nil {
		return "", gerror.WrapCode(gcode.CodeInvalidParameter, err, "c encode failed")
	}
	return string(dst), nil
}

func createAESIVWithKey(key string) string {
	s := strings.ToUpper(gmd5.MustEncryptString(key))
	arr := []byte{}
	for i := 0; i < len(s); i += 2 {
		arr = append(arr, s[i])
	}
	return string(arr)
}

func splitContentAndKey(content string) (c string, k string) {

	if len(content) >= (256 + 32) {
		ps := []string{}
		cs := []string{}
		for i := 0; i < 4; i++ {
			pass := content[0:64]
			content = content[64:]

			dContent := ""
			if i == 3 {
				dContent = content
			} else {
				dContent = content[0:8]
				content = content[8:]
			}

			ps = append(ps, pass)
			cs = append(cs, dContent)
		}

		c = strings.Join(cs, "")
		k = strings.Join(ps, "")
	}

	return
}

func checkAlgoByContentAndTimestamp(content string, time int64, origin string) error {
	a, err := gmd5.Encrypt(content)
	if err != nil {
		return gerror.WrapCode(gcode.CodeInvalidParameter, err, "md5A encode failed")
	}
	md5A := gstr.Reverse(strings.ToUpper(a))
	md5B, err := gmd5.Encrypt(md5A)
	if err != nil {
		return gerror.WrapCode(gcode.CodeInvalidParameter, err, "md5B encode failed")
	}
	md5ABytes := []byte(md5A)
	md5BBytes := []byte(md5B)
	md5C := string(append(md5BBytes[0:8], md5ABytes[8:]...))
	md5D := gstr.Reverse(gmd5.MustEncrypt(formatBinaryWithContent(md5C) + strconv.FormatInt(time, 10)))
	sha1StringA := formatBinaryWithContent(gsha1.Encrypt(md5D))
	sha1StringB := gstr.Reverse(gmd5.MustEncrypt(sha1StringA + md5C))
	list := doSha([]string{}, sha1StringB, md5A, md5B, md5C, md5D, 1)
	if origin != strings.Join(list, "") {
		return gerror.WrapCode(gcode.CodeInvalidParameter, errors.New("wrong algo"), "algo check failed")
	}
	return nil
}

func formatBinaryWithContent(content string) string {
	res := ""
	arr := []byte(content)
	for i := 0; i < len(arr); i++ {
		str := strconv.FormatInt(int64(arr[i]), 2)
		res += str
	}
	return res
}

func doSha(list []string, sha, md5A, md5B, md5C, md5D string, count int) []string {
	size := len(list) + count

	sha = gmd5.MustEncrypt(sha + strconv.FormatInt(int64(size), 10))
	md5A = gmd5.MustEncrypt(md5A + strconv.FormatInt(int64(size), 10))
	md5B = gmd5.MustEncrypt(md5B + strconv.FormatInt(int64(size), 10))
	md5C = gmd5.MustEncrypt(md5C + strconv.FormatInt(int64(size), 10))
	md5D = gmd5.MustEncrypt(md5D + strconv.FormatInt(int64(size), 10))

	baseStr := ""
	switch count {
	case 1:
		baseStr = sha
		break
	case 2:
		baseStr = md5A
		break
	case 3:
		baseStr = md5B
		break
	case 4:
		baseStr = md5C
		break
	case 5:
		baseStr = md5D
		break
	}

	b := []byte(baseStr)
	index, n, maxLength := 0, 0, 16
	for i := 0; i < len(b); i++ {
		m := int(b[i])
		if n <= m {
			n = m
			charStr := ""
			if index == 4 {
				index = 0
			} else {
				index = index + 1
			}
			switch index {
			case 1:
				charStr = string(md5A[i])
				break
			case 2:
				charStr = string(md5B[i])
				break
			case 3:
				charStr = string(md5C[i])
				break
			case 4:
				charStr = string(md5D[i])
				break
			}

			if len(list) < maxLength {
				if charStr != "" {
					list = append(list, charStr)
				}
			} else {
				return list
			}
		}
	}

	if count < 5 {
		if len(list) < maxLength {
			list = doSha(list, sha, md5A, md5B, md5C, md5D, count+1)
		}
	} else {
		len := maxLength - len(list)
		for i := 0; i < len; i++ {
			list = append(list, "0")
		}
	}
	return list
}
