//go:build loadsim

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	bnats "github.com/mustra-dev/mustra/internal/nats"
)

// runJWTSize builds the legacy shared-credential user JWT the auth callout
// issues (natsauth_callout.go), with its per-enrolled-agent deny list, for
// several fleet sizes, and reports its size and the cost of signing it and
// of the broker decoding it. nats-server's max_payload (8 MB in nats.conf)
// bounds the callout response that carries it.
func runJWTSize(args []string) {
	fs := flag.NewFlagSet("jwtsize", flag.ExitOnError)
	sizes := fs.String("n", "0,100,1000,5000,10000,20000,50000", "enrolled-agent counts")
	_ = fs.Parse(args)
	account, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	userPub, _ := user.PublicKey()
	fmt.Printf("%8s %12s %14s %10s %10s %8s %8s\n", "enrolled", "jwt_bytes", "response_bytes", "sign_ms", "decode_ms", "pub_deny", "sub_deny")
	for _, s := range strings.Split(*sizes, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			fatal(err)
		}
		ids := make([]string, n)
		for i := range ids {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			ids[i] = "agt-" + hex.EncodeToString(b)
		}
		st := time.Now()
		perms := bnats.LegacyAgentPermissionsExcept(ids)
		uc := jwt.NewUserClaims(userPub)
		uc.Name = bnats.LegacyAgentUser
		uc.Audience = "$G"
		uc.Expires = time.Now().Add(10 * time.Minute).Unix()
		uc.Pub.Allow.Add(perms.PubAllow...)
		uc.Sub.Allow.Add(perms.SubAllow...)
		uc.Pub.Deny.Add(perms.PubDeny...)
		uc.Sub.Deny.Add(perms.SubDeny...)
		userJWT, err := uc.Encode(account)
		if err != nil {
			fmt.Printf("%8d  user JWT cannot be encoded: %v (pub_deny %d, sub_deny %d)\n", n, err, len(perms.PubDeny), len(perms.SubDeny))
			continue
		}
		resp := jwt.NewAuthorizationResponseClaims(userPub)
		resp.Jwt = userJWT
		respJWT, err := resp.Encode(account)
		if err != nil {
			fmt.Printf("%8d %12d  callout response cannot be encoded: %v\n", n, len(userJWT), err)
			continue
		}
		sign := time.Since(st)
		st = time.Now()
		_, derr := jwt.DecodeAuthorizationResponseClaims(respJWT)
		if derr == nil {
			_, derr = jwt.DecodeUserClaims(userJWT)
		}
		dec := time.Since(st)
		if derr != nil {
			// What the broker does with it: nats-server decodes the
			// response with this same library and refuses the connection.
			fmt.Printf("%8d %12d %14d %10.1f  broker cannot decode: %v\n", n, len(userJWT), len(respJWT), ms(sign), derr)
			continue
		}
		fmt.Printf("%8d %12d %14d %10.1f %10.1f %8d %8d\n", n, len(userJWT), len(respJWT), ms(sign), ms(dec), len(perms.PubDeny), len(perms.SubDeny))
	}
}
