package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/nats-io/jwt/v2"
	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/store"
)

// The broker's auth callout responder.
//
// nats-server sends every connection that is not one of its configured
// auth_users (the server's own account) here as a signed authorization
// request. The answer is a user JWT, signed with the callout account key
// the broker was configured to trust, carrying the permissions for the one
// identity the connection proved — or an error, which the broker turns
// into an authorization violation.
//
// Every JWT expires. Expiry is how a decision made here is revisited: when
// it lapses the broker disconnects the client, the client reconnects, and
// this runs again — so a revoked credential, a deleted token or the legacy
// toggle being switched off takes effect within one lifetime without the
// server needing a system account to kick anyone.

const (
	agentJWTLifetime  = time.Hour
	enrollJWTLifetime = 2 * time.Minute
	// globalAccount is the account every user lives in when nats.conf
	// defines no accounts, which ours does not.
	globalAccount = "$G"
)

// calloutWorkers is how many authorization requests are decided at once.
//
// A NATS subscription delivers its messages one at a time, so answering in
// the handler itself decides the whole fleet's connections in single file:
// each one waits for every database round trip and signature ahead of it.
// That is what a broker restart, or a fleet whose JWTs were issued
// together, puts in front of this — thousands of connections inside a few
// seconds, each held until its answer or the broker's timeout. Bounded,
// because each decision holds a database connection, and the handler
// blocking when all are busy is the backpressure.
const calloutWorkers = 16

func (s *Server) subscribeAuthCallout(ctx context.Context) (*gonats.Subscription, error) {
	// A queue group, so two control-plane instances answer each request
	// once between them rather than racing to answer it twice.
	return s.nc.QueueSubscribe(bnats.AuthCalloutSubject, "mustra-auth", boundedHandler(calloutWorkers, func(msg *gonats.Msg) {
		token, admitted, err := s.answerAuthCallout(ctx, msg.Data)
		if err != nil {
			s.logger.Error("auth callout could not answer", "error", err)
			return // the broker times the connection out, which denies it
		}
		// Not respondToAgent: this request comes from the broker itself
		// (agents cannot publish on the callout subject), and its reply is
		// the broker's own system inbox.
		_ = msg.Respond([]byte(token))
		// Bookkeeping after the answer, not before it: the broker holds
		// the connection until it hears back and refuses it once its
		// authorization timeout passes, so a write on the way — a commit
		// competing for the pool with every other callout of a reconnect
		// storm — only made more of them miss it.
		if admitted != "" {
			if err := s.store.TouchAgentAuth(ctx, admitted); err != nil {
				s.logger.Debug("record agent auth failed", "agent_id", admitted, "error", err)
			}
		}
	}))
}

// boundedHandler runs handle for each message on its own goroutine, at most
// workers at a time; the subscription's delivery blocks while all are busy.
// Only for handlers whose messages are independent of each other's order.
func boundedHandler(workers int, handle gonats.MsgHandler) gonats.MsgHandler {
	sem := make(chan struct{}, workers)
	return func(msg *gonats.Msg) {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			handle(msg)
		}()
	}
}

// answerAuthCallout decodes one request and returns the signed response,
// and the enrolled agent it admitted, if any, for the caller to record.
func (s *Server) answerAuthCallout(ctx context.Context, data []byte) (string, string, error) {
	req, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		return "", "", err
	}
	resp := jwt.NewAuthorizationResponseClaims(req.UserNkey)
	resp.Audience = req.Server.ID
	resp.Expires = time.Now().Add(time.Minute).Unix()

	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	perms, name, lifetime, denial := s.authorizeConnection(dctx, req.ConnectOptions.Username, req.ConnectOptions.Password)
	admitted := ""
	if denial != "" {
		// The reason is for our log only. The broker reports every
		// rejection to the client as the same authorization violation.
		s.logger.Info("broker connection refused", "user", req.ConnectOptions.Username,
			"host", req.ClientInformation.Host, "reason", denial)
		resp.Error = "not authorized"
	} else {
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Name = name
		uc.Audience = globalAccount
		uc.IssuedAt = time.Now().Unix()
		uc.Expires = time.Now().Add(lifetime).Unix()
		uc.Pub.Allow.Add(perms.PubAllow...)
		uc.Sub.Allow.Add(perms.SubAllow...)
		uc.Pub.Deny.Add(perms.PubDeny...)
		uc.Sub.Deny.Add(perms.SubDeny...)
		if perms.AllowResponses {
			// One reply per request, within the longest a server request
			// waits (a compliance run, ten minutes) with room to spare.
			uc.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Hour}
		}
		userJWT, err := uc.Encode(s.trust.calloutKey)
		if err != nil {
			return "", "", err
		}
		resp.Jwt = userJWT
		if bnats.ValidAgentID(name) {
			admitted = name
		}
	}
	token, err := resp.Encode(s.trust.calloutKey)
	return token, admitted, err
}

// jitter spreads expiry so a fleet that connected together does not
// reconnect together every hour.
func jitter(d time.Duration) time.Duration {
	return d - time.Duration(rand.Int64N(int64(d/5)))
}

// authorizeConnection decides one connection from its username and
// password. It returns the permission set, the user name to put in the
// JWT, its lifetime, and a non-empty denial reason when refused.
func (s *Server) authorizeConnection(ctx context.Context, user, pass string) (bnats.Permissions, string, time.Duration, string) {
	switch {
	case bnats.ValidAgentID(user):
		stored, err := s.store.AgentCredentialHash(ctx, user)
		if err != nil {
			return bnats.Permissions{}, "", 0, "credential lookup failed: " + err.Error()
		}
		if stored == "" || !secretMatches(stored, pass) {
			return bnats.Permissions{}, "", 0, "unknown or revoked agent credential"
		}
		perms, err := bnats.AgentPermissions(user)
		if err != nil {
			return bnats.Permissions{}, "", 0, err.Error()
		}
		// last_auth_at is recorded by the subscriber, after it has answered.
		return perms, user, jitter(agentJWTLifetime), ""

	case user == bnats.LegacyAgentUser || (s.trust.legacyUser != "" && user == s.trust.legacyUser):
		// The shared password every agent once held is retired (#231): with
		// identity enforced, an agent connects with its own credential or
		// an enrollment token, never as "the agents".
		return bnats.Permissions{}, "", 0, "the legacy shared agent credential is retired; enroll this agent with a token"
	}

	nonce, legacy, ok := bnats.ParseEnrollUser(user)
	if !ok {
		return bnats.Permissions{}, "", 0, "unrecognised user"
	}
	if legacy {
		return bnats.Permissions{}, "", 0, "legacy enrolment is retired; enroll this agent with a token"
	}
	if _, err := s.store.LookupEnrollmentToken(ctx, hashToken(pass)); err != nil {
		if !errors.Is(err, store.ErrTokenUnusable) {
			return bnats.Permissions{}, "", 0, "token lookup failed: " + err.Error()
		}
		return bnats.Permissions{}, "", 0, "enrollment token unknown, expired, revoked or used up"
	}
	perms, err := bnats.EnrollPermissions(nonce, legacy)
	if err != nil {
		return bnats.Permissions{}, "", 0, err.Error()
	}
	return perms, user, enrollJWTLifetime, ""
}

// hashToken / hashSecret: SHA-256, hex. Both values are 32 random bytes, so
// there is nothing for a slow hash to protect against.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func secretMatches(storedHash, secret string) bool {
	if secret == "" {
		return false
	}
	got := hashToken(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}
