//go:build !windows

package agent

func machineStoreCertificates(string) [][]byte { return nil }
