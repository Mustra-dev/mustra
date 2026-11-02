//go:build !windows

package agent

import (
	"context"
	"errors"

	"github.com/mustra-dev/mustra/internal/proto"
)

func certADCSSubmit(context.Context, proto.CertJob) (string, error) {
	return "", errors.New("AD CS requests are submitted from a Windows endpoint in the domain")
}

func certADCSCA(context.Context, proto.CertJob) (string, error) {
	return "", errors.New("the AD CS CA certificate is fetched from a Windows endpoint in the domain")
}

func certADCSRevoke(context.Context, proto.CertJob) (string, error) {
	return "", errors.New("AD CS revocations run on a Windows endpoint in the domain")
}
