package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"github.com/dgryski/dgoogauth"
	"github.com/disintegration/imaging"
	"image"
	"net/http"
	"os"
	"rsc.io/qr"
	"strings"
)

func randStr(strSize int, randType string) string {
	var dictionary string

	if randType == "alphanum" {
		dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "alpha" {
		dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "number" {
		dictionary = "0123456789"
	}

	var bytes = make([]byte, strSize)
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(bytes)
}

// need this to be global variable
var secret string

func Verify(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		token := r.FormValue("token")

		// setup the one-time-password configuration.
		otpConfig := &dgoogauth.OTPConfig{
			Secret: strings.TrimSpace(secret),
			WindowSize:  3,
			HotpCounter: 0,
		}

		trimmedToken := strings.TrimSpace(token)

		// Validate token
		ok, err := otpConfig.Authenticate(trimmedToken)

		// if the token is invalid or expired
		if err != nil {
			w.Write([]byte(fmt.Sprintf("<html><body><h1>Token [%s] verification : %v</h1></body></hmtl>", token, ok)))
		}

		// token validated and proceed to login, bla, bla....
		w.Write([]byte(fmt.Sprintf("<html><body><h1>Token [%s] verification : %v</h1></body></hmtl>", token, ok)))

	}

}

func Home(w http.ResponseWriter, r *http.Request) {

	//w.Write([]byte(fmt.Sprintf("Generating QR code\n")))

	// generate a random string - preferbly 6 or 8 characters
	randomStr := randStr(6, "alphanum")

	// For Google Authenticator purpose
	// for more details see
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	secret = base32.StdEncoding.EncodeToString([]byte(randomStr))
	//w.Write([]byte(fmt.Sprintf("Secret : %s !\n", secret)))

	// authentication link. Remember to replace SocketLoop with yours.
	// for more details see
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	authLink := "otpauth://totp/SocketLoop?secret=" + secret + "&issuer=SocketLoop"

	// Encode authLink to QR codes
	// qr.H = 65% redundant level
	// see https://godoc.org/code.google.com/p/rsc/qr#Level

	code, err := qr.Encode(authLink, qr.H)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	imgByte := code.PNG()

	// convert byte to image for saving to file
	img, _, _ := image.Decode(bytes.NewReader(imgByte))

	err = imaging.Save(img, "./QRImgGA.png")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// in real world application, the QRImgGA.png file should
	// be a temporary file with dynamic name.
	// for this tutorial sake, we keep it as static name.

	w.Write([]byte(fmt.Sprintf("<html><body><h1>QR code for : %s</h1><img src='http://localhost:8080/QRImgGA.png'>", authLink)))
	w.Write([]byte(fmt.Sprintf("<form action='http://localhost:8080/verify' method='post'>Token : <input name='token' id='token'><input type='submit' value='Verify Token'></form></body></html>")))
}

func main() {
	http.HandleFunc("/", Home)
	http.HandleFunc("/verify", Verify)

	// this is for displaying the QRImgGA.png from the source directory
	http.Handle("/QRImgGA.png", http.FileServer(http.Dir("./")))

	http.ListenAndServe(":8080", nil)
}