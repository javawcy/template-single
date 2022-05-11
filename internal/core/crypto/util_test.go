package cecrypto

import (
	"testing"
)

func TestDecodeC(t *testing.T) {
	type args struct {
		content string
		time    int64
		pub     string
		pri     string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "testC", args: args{
			content: "892f4ba1031c0e00b8f7beb16363eb8eebf8727d7720731a12fac8f4de7cd52e2dbe4e01f7a60467036adfd3aa62c5010474ce83b991d29a877d33894a312ee006a74e3f29d98ec2be8125836f1117596640a9299d5c095f837589a48b90bc07fe0aa004d9fcabe8f3c8367cde68e215540ba851fe771de6debd8116fd514bcf31ac52847b433c2e63b489ba6674b263040f1ca37e9438ca652007b015394543a67ff9987c98a8022822911154aea56865e9c9b02d51817f4bc7956a3496a70eab5c54d93ff699b2515faee7705fce222b3f1a99f23b77219dda3402242879ba653bc5eab7419ec47f0c889065527b52b0353b114940d945e934bd1dd28795c390ea6835df16ca858615a5729c855bd47b9c559d4c372550c2823d8310bc6b6a3112961a88475d46623231627e930177ea07dd7430a0e689bb23e9399dd42181aca2ba074053be65d5e34d65331cc302a4086ff5bd1a1825364da80d182dbaf3d638c8cb57587b5da37ef7f1384f9770c7314b72ae5949784beaa30727a54166ee2bc2a95e708ee10dc911a78e2fdfca565e9f2377ec95765525eaed0909b33b397f34844178784a66ec5d300dd946d57997922f8014c2d850c0ea5374df153550cea5fb69df6862f9f90a0446a379088f572cbddcfd5bfbe6a19940d8fe7f13e2515401caeab0762b584f4baacc48c999d02018d1df2f8adee53806054d7e39dc42833eac197d4e2ce9c71413831fbfdd2476bde7d8f4b478b1cd62cd608398b39f64cd2d68e453b16bf5ccfb948db72a4a4a52624b57536dbfa360d7626fa81f8981021a4240ff4751eb2693cef4221dc17350c32de497f482435a78299f6f69eec4447b4212e195aa2045beb38c22",
			time:    1651219583056,
			pub:     "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3XqeQKHBSsN498dg3+TqwM3yq87ZN2kGcSU+XeczHxwBbCzBfab8jJoRm1VvHK00GbsuH+bq8e0jAgzIUlqNahbvxKPmB9i6WiPunTg126VzhbAXM4CntiVtzhqAe5eI4FI93PEwxhmr8H6c6KnlsOPrS+5TA4Q7xqp0Ht+X5ZwIDAQAB\n-----END PUBLIC KEY-----",
			pri:     "-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALdep5AocFKw3j3x2Df5OrAzfKrztk3aQZxJT5d5zMfHAFsLMF9pvyMmhGbVW8crTQZuy4f5urx7SMCDMhSWo1qFu/Eo+YH2LpaI+6dODXbpXOFsBczgKe2JW3OGoB7l4jgUj3c8TDGGavwfpzoqeWw4+tL7lMDhDvGqnQe35flnAgMBAAECgYB15nxiqj2eTW538boOM0dS56fu2wiKghzReimcwYmzofZOk6Ekl/93gFp9LA34v5Sk4DQpV56DddlPPovCxSB+Cj9i+itOJy3+HfniUb3CeRG3N8ReWQK/vzsy1r78UlSW0caTjmD6numFufm+bIRT50qo9mRO16qabB8gLJGsgQJBAOlk+P7642CKSkXZM9oNk6QTY6kgXEgloM35x2EBTslu6fYXiPv2sFVkyrWCfvzT6/sZWWFgqcBUoFWEsP/sJkcCQQDJIVE32DKNEAdq2s89nPshGgFRiLr7t7KzE7OxWlBT8tevc9omAz1FRCH2UMMo3eOce0ZxMAll2wz+SDjnLoPhAkEAqxjmoKX0AlXe1Q3BwVyqm2HLcbTTceCD3fv6edanl2vEADCIr43M/w0AvceIqHgDSvTuXUCrsN9ZGthHmZXZCQJAAIZYuueSgjG3gzzc65E8SoLR3A+aRUveaH81qdHNgdqRW4DW4eCCSWr7F7RwPewOSvs7XNI+RAjFSOiRVXEWoQJAKQ5QM0PoirWmlaaMwIcBvxHYLlemjf5qmwzGehN9ehdRBTDQOAqrcW2s2WxV7phT3Y+8V2rWl2VbaMqC587myA==\n-----END PRIVATE KEY-----",
		}, want: "{\n  \"appVersion\" : \"3.5.9\",\n  \"idfa\" : \"00000000-0000-0000-0000-000000000000\",\n  \"idfv\" : \"2bf67b41-1451-46d0-bacd-1328770a7cb2\",\n  \"firstOpen\" : 1639129599294,\n  \"appBundleId\" : \"com.maoerduo.tomatosign.Widget\",\n  \"channel\" : \"unKnow\",\n  \"deviceId\" : \"9D5A3CD8-A508-4B25-A4E2-ADAAF336DBED\",\n  \"isInjection\" : \"false\",\n  \"appMD5\" : \"c1dad12bfc24f1c0cc9c74e5e639f6b8\",\n  \"isJailBreak\" : \"false\",\n  \"osVersion\" : \"15.4.1\",\n  \"phoneModel\" : \"iPhone13,2\",\n  \"regions\" : \"zh-Hans-CN\"\n}", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeC(tt.args.content, tt.args.time, tt.args.pub, tt.args.pri)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DecodeC() = %v, want %v", got, tt.want)
			}
		})
	}
}
