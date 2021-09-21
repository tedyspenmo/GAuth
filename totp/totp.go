package totp

import (
	"crypto"
	"encoding/base32"
	"errors"
	"fmt"
	"github.com/dgryski/dgoogauth"
	"strings"
)

import (
	"crypto/rand"
	qr2 "rsc.io/qr"
)

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
	defaultIssuer = "Spenmo"
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
		Secret: strings.TrimSpace(token),
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

// example: otpauth://totp/Spenmo:tedy@spenmo.com?secret=JBSWY3DPEHEW3PXP&issuer=Spenmo
func (t *Totp) CreateUrl() string {
	scheme := "otpauth"
	host := "totp"
	account := fmt.Sprintf("%s:%s", t.issuer, t.account)
	parameter := fmt.Sprintf("secret=%s&issuer=%s", t.secret, t.issuer)

	return fmt.Sprintf("%s://%s:%s?%s", scheme, host, account, parameter)
}
