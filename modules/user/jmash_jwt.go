package user

import (
    "fmt"
    "encoding/json"

    "github.com/lestrrat-go/jwx/v3/jwk"
    "github.com/lestrrat-go/jwx/v3/jwa"
    "github.com/lestrrat-go/jwx/v3/jws"
    "github.com/lestrrat-go/jwx/v3/jwe"
)

//Token登录信息
type JmashToken struct {
	UserId    string        `json:"upn"`
	Subject   string        `json:"sub"`  
	Tenant    string        `json:"iss"` 
	TokenId   string        `json:"jti"`
	Client    string        `json:"azp"`
}

// 从配置文件中加载公钥和私钥
func loadKeysFromConfig(publicKeyPEM string,privateKeyPEM string) (jwk.Key, jwk.Key, error) {
	
    // 解析公钥
    publicKey, err := jwk.ParseKey([]byte("-----BEGIN PUBLIC KEY-----\n"+publicKeyPEM+"\n-----END PUBLIC KEY-----"), jwk.WithPEM(true))
	if err != nil {
	   fmt.Printf("failed to parse key in PEM format: %s\n", err)
	   return nil, nil, err
	}

    // 解析私钥
    privateKey, err := jwk.ParseKey([]byte("-----BEGIN PRIVATE KEY-----\n"+privateKeyPEM+"\n-----END PRIVATE KEY-----"), jwk.WithPEM(true))
	if err != nil {
	   fmt.Printf("failed to parse key in PEM format: %s\n", err)
	   return nil, nil, err
	}
	
    return publicKey, privateKey, nil
}

// 验证 JWT
func VerifyJWT(jweToken string,decryptKey string,verifySignKey string) (JmashToken,error) {
    // 加载公钥和私钥
    publicKey, privateKey, err := loadKeysFromConfig(verifySignKey,decryptKey)
    if err != nil {
        return JmashToken{}, fmt.Errorf("failed to verify session token: %w", err)
    }
    
    decrypted, err := jwe.Decrypt([]byte(jweToken), jwe.WithKey(jwa.RSA_OAEP(), privateKey))
    if err != nil {
      fmt.Printf("failed to decrypt payload: %s\n", err)
      return JmashToken{}, fmt.Errorf("failed to verify session token: %w", err)
    }
    fmt.Printf("%s\n", decrypted)

    buf, err := jws.Verify([]byte(decrypted), jws.WithKey(jwa.RS256(), publicKey))
    if err != nil {
      fmt.Printf("failed to verify payload: %s\n", err)
      return JmashToken{}, fmt.Errorf("failed to verify session token: %w", err)
    }
    fmt.Printf("%s\n", buf)

    var token JmashToken
    // 使用 json.Unmarshal 将字符串解码为结构体
    err1 := json.Unmarshal([]byte(buf), &token)
    if err != nil {
        return JmashToken{}, fmt.Errorf("failed to Unmarshal token: %w", err1)
    }
    return token, nil
}


