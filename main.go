package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	//Create pairs of private and public key and store them in a file
	GenerateKeys()
	token, _, _ := GenerateSignedJWT("34567")
	err := ValidateJWT(token)
	fmt.Println(err)
}

func GenerateKeys() {

	// Generate a new RSA private key with 2048 bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA private key:", err)
		os.Exit(1)
	}

	// Encode the private key to the PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println("Error creating private key file:", err)
		os.Exit(1)
	}
	pem.Encode(privateKeyFile, privateKeyPEM)
	privateKeyFile.Close()

	// Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	// Encode the public key to the PEM format
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}
	publicKeyFile, err := os.Create("public_key.pem")
	if err != nil {
		fmt.Println("Error creating public key file:", err)
		os.Exit(1)
	}
	pem.Encode(publicKeyFile, publicKeyPEM)
	publicKeyFile.Close()

	fmt.Println("RSA key pair generated successfully!")

}

func GenerateRefreshToken(id string) (string, string, error) {
	var mySigningKey = []byte(os.Getenv("JWT_KEY"))
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	exp := time.Now().Add(time.Hour * 24 * 2).Unix() // 2 days
	expiryTime := time.Unix(exp, 0).Format("2006-01-02 15:04:05")

	claims["id"] = id
	claims["exp"] = exp

	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		return "", "", err
	}

	return tokenString, expiryTime, nil
}

func GenerateSignedJWT(id string) (token string, tokenExpiryTime time.Time, err error) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println("error reading working directory")
		return
	}

	keyFile := "private_key.pem"

	var mySigningKey *os.File
	mySigningKey, err = os.Open(path.Join(wd, keyFile))
	if err != nil {
		fmt.Println("error opening the sceyt private key", err)
		return
	}
	var keyBytes []byte
	if keyBytes, err = io.ReadAll(mySigningKey); err != nil {
		fmt.Println("error unable to convert the key file to bytes", err)
		return
	}

	key, _err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)

	if _err != nil {
		err = fmt.Errorf("error parsing key ==> %w", _err)
		return
	}

	tokenExpiryTime = time.Now().Add(time.Minute * 30)

	claims := make(jwt.MapClaims)
	//your token claims goes here
	claims["id"] = id
	claims["exp"] = tokenExpiryTime.Unix()

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Generate the token
	token, err = jwtToken.SignedString(key)
	if err != nil {
		fmt.Println("error signing the token with sceyt token", err)
		return
	}

	return
}

func ValidateJWT(token string) error {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("invalid token sign method")
		}
		//rea key from file
		pem, err := os.ReadFile("public_key.pem")
		if err != nil {
			return nil, err
		}
		//parse the bytes to rsa publickey format
		rsaPublicKey, _ := jwt.ParseRSAPublicKeyFromPEM(pem)
		if rsaPublicKey == nil {
			return nil, errors.New("failed to parse the public key")
		}
		return rsaPublicKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return errors.New("token validation failed")
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			return errors.New("token validation failed")
		}
		if errors.Is(err, jwt.ErrTokenUnverifiable) {

			return errors.New("token validation failed")
		}
	}

	return nil
}
