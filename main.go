package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"github.com/dgryski/dgoogauth"
	"github.com/disintegration/imaging"
	"image"
	"net/http"
	"os"
	qr2 "rsc.io/qr"
	"strings"
)

// need this to be global variable
var secret string

func Verify(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		token := r.FormValue("token")

		// setup the one-time-password configuration.
		totp, err := TOTPBySecretKey(secret, "tedy@gmail.com")

		err = totp.Validate(token)
		// if the token is invalid or expired
		if err != nil {
			w.Write([]byte(fmt.Sprintf("<html><body><h1>Token [%s] verification : %v</h1></body></hmtl>", token, false)))
			return
		}

		// token validated and proceed to login, bla, bla....
		w.Write([]byte(fmt.Sprintf("<html><body><h1>Token [%s] verification : %v</h1></body></hmtl>", token, true)))

	}

}

func Home(w http.ResponseWriter, r *http.Request) {

	totp, err := NewTOTP("tedy@gmail.com")
	if err != nil {
		return
	}

	secret = totp.secret
	imgByte, err := totp.QR()

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

	w.Write([]byte(fmt.Sprintf("<html><body><h1>QR code for : %s</h1><img src='http://localhost:8080/QRImgGA.png'>", totp.CreateUrl())))
	w.Write([]byte(fmt.Sprintf("<form action='http://localhost:8080/verify' method='post'>Token : <input name='token' id='token'><input type='submit' value='Verify Token'></form></body></html>")))
}

func main() {
	http.HandleFunc("/", Home)
	http.HandleFunc("/verify", Verify)

	// this is for displaying the QRImgGA.png from the source directory
	http.Handle("/QRImgGA.png", http.FileServer(http.Dir("./")))

	http.ListenAndServe(":8080", nil)
}



type Totp struct {
	secret                    string             // this is the secret key
	window					  int				 // Make it check after and before the current time
	issuer                    string             // the company name
	account                   string             // email/username
	stepSize                  int                // by default 30 seconds
	hashFunction              crypto.Hash        // Google Authenticaotr always use SHA1
}

const (
	defaultWindow = 5
	defaultIssuer = "spenmo"
	defaultStepSize = 30
	defaultHash   = crypto.SHA1
)

func NewTOTP(account string) (totp *Totp, err error){
	// Generating key, It will make sure the key always different
	keySize := defaultHash.Size()
	key := make([]byte, keySize)
	total, err := rand.Read(key)
	if err != nil {
		err = errors.New(fmt.Sprintf("TOTP failed to create because there is not enough entropy, we got only %d random bytes", total))
		return
	}
	secret := base32.StdEncoding.EncodeToString(key)

	totp = &Totp{
		secret:       secret,
		window:       defaultWindow,
		issuer:       defaultIssuer,
		account:      account,
		stepSize:     defaultStepSize,
		hashFunction: defaultHash,
	}
	return
}

func TOTPBySecretKey(secreteKey string, account string) (totp *Totp, err error){
	totp = &Totp{
		secret:       secreteKey,
		window:       defaultWindow,
		issuer:       defaultIssuer,
		account:      account,
		stepSize:     defaultStepSize,
		hashFunction: defaultHash,
	}
	return
}

func (t *Totp) QR() (qrCode []byte, err error){
	url := t.CreateUrl()

	qr, err := qr2.Encode(url, qr2.M)
	if err != nil {
		return
	}

	return qr.PNG(), err
}

func (t *Totp) Validate(token string) (err error) {

	// setup the one-time-password configuration.
	otpConfig := &dgoogauth.OTPConfig{
		Secret: strings.TrimSpace(t.secret),
		WindowSize:  t.window,
		HotpCounter: 0,
		UTC: true,
	}

	trimmedToken := strings.TrimSpace(token)

	// Validate token
	ok, err := otpConfig.Authenticate(trimmedToken)
	if !ok {
		err = errors.New("token mismatch")
	}
	return
}

func (otp *Totp) Secret() string {
	return base32.StdEncoding.EncodeToString([]byte(otp.secret))
}

// example: otpauth://totp/Spenmo:tedy@spenmo.com?secret=JBSWY3DPEHEW3PXP&issuer=Spenmo
func (t *Totp) CreateUrl() string {

	scheme := "otpauth"
	host := "totp"
	account := fmt.Sprintf("%s:%s", t.issuer, t.account)
	parameter := fmt.Sprintf("secret=%s&issuer=%s", t.secret, t.issuer)

	return fmt.Sprintf("%s://%s/%s?%s", scheme, host, account, parameter)
}
