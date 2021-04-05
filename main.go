package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	var r int

	//'archivo.txt' tiene su firma digital con 'hola como estas?' de contenido
	fmt.Println("Bienvenido")
	fmt.Println("1. Crear Firma Digital Del Archivo 'archivo.txt'")
	fmt.Println("2. Verificar Firma Digital Del Archivo 'archivo.txt'")

	fmt.Print("> ")

	fmt.Scan(&r)

	switch r {
	case 1:
		sourceData, err := ioutil.ReadFile("archivo.txt")

		if err != nil {
			log.Fatal(err)
		}

		signData, err := SignatureRSA(sourceData)

		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile("firma.sha256", signData, 0644)

		if err != nil {
			log.Fatal(err)
		}

	case 2:

		signData, err := ioutil.ReadFile("firma.sha256")

		if err != nil {
			log.Fatal(err)
		}

		sourceData, err := ioutil.ReadFile("archivo.txt")

		if err != nil {
			log.Fatal(err)
		}

		err = VerifyRSA(sourceData, signData)

		if err != nil {
			fmt.Println("Status: Not OK")
			os.Exit(1)
		}

		fmt.Println("Status: OK")

	default:
		log.Fatal("No es Opcion Valida")
	}

}

func SignatureRSA(sourceData []byte) (signatureData []byte, err error) {

	privateKey, err := getPrivateKey()

	if err != nil {
		return
	}

	myHash := sha256.New()

	myHash.Write(sourceData)

	hashRes := myHash.Sum(nil)

	signatureData, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashRes)

	if err != nil {
		return
	}
	return
}

func VerifyRSA(sourceData, signedData []byte) (err error) {

	publicKey, err := getPublicKey()

	if err != nil {
		return
	}

	mySha := sha256.New()

	mySha.Write(sourceData)

	res := mySha.Sum(nil)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, res, signedData)

	if err != nil {
		return
	}

	return

}

func getPrivateKey() (privateKey *rsa.PrivateKey, err error) {

	dataKeyPrivate, err := ioutil.ReadFile("key.pem")

	if err != nil {
		return
	}

	block, _ := pem.Decode(dataKeyPrivate)

	enc := x509.IsEncryptedPEMBlock(block)

	b := block.Bytes

	if enc {

		b, err = x509.DecryptPEMBlock(block, nil)

		if err != nil {
			return
		}

	}

	privateKey, err = x509.ParsePKCS1PrivateKey(b)

	if err != nil {
		return
	}

	return
}

func getPublicKey() (publicKey *rsa.PublicKey, err error) {

	dataKeyPublic, err := ioutil.ReadFile("public.pem")

	if err != nil {
		return
	}

	block, _ := pem.Decode(dataKeyPublic)

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if enc {

		b, err = x509.DecryptPEMBlock(block, nil)

		if err != nil {
			return
		}

	}

	ifc, err := x509.ParsePKIXPublicKey(b)

	if err != nil {

		return

	}

	publicKey, ok := ifc.(*rsa.PublicKey)

	if !ok {

		log.Fatal("no es llave publica")

	}
	return
}
