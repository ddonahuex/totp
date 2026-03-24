package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

// GenerateTOTP calculates a 6-digit code based on RFC 6238
func GenerateTOTP(secret string) (string, error) {
	// 1. Decode Base32 Secret
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %v", err)
	}

	// 2. Calculate Time Step (30s interval)
	epoch := time.Now().Unix()
	counter := uint64(math.Floor(float64(epoch) / 30.0))

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	// 3. HMAC-SHA1
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// 4. Dynamic Truncation
	offset := sum[len(sum)-1] & 0xf
	binaryCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	otp := binaryCode % 1000000
	return fmt.Sprintf("%06d", otp), nil
}

func main() {
	// Precedence: CLI Flag > Env Var > Default
	cliSecret := flag.String("secret", "", "HIPAAVault 2FA Secret")
	cliPass := flag.String("pass", "", "SFTP Default Password")
	flag.Parse()

	secret := *cliSecret
	if secret == "" {
		secret = os.Getenv("HV_SECRET")
	}
	if secret == "" {
		secret = "123456789" // Fallback
	}

	password := *cliPass
	if password == "" {
		password = os.Getenv("HV_PASSWORD")
	}
	if password == "" {
		password = "abcdefg" // Fallback
	}

	totp, err := GenerateTOTP(secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated TOTP: %s\n", totp)
	fmt.Printf("SFTP Password:  %s%s\n", password, totp)
}
