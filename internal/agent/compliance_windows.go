//go:build windows

package agent

import (
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Registry rules are what Windows CIS benchmarks are made of — 967 of the
// 1,016 rules in the CIS Windows Server 2025 policy are registry lookups.
// Without this the Windows benchmarks would parse and then answer
// "unknown" for almost everything, which is honest but useless.
//
// Form: r:<key> -> <value name> -> <matcher>
// A rule with no value name asks only whether the key exists.

var registryRoots = map[string]registry.Key{
	"HKEY_LOCAL_MACHINE": registry.LOCAL_MACHINE, "HKLM": registry.LOCAL_MACHINE,
	"HKEY_CURRENT_USER": registry.CURRENT_USER, "HKCU": registry.CURRENT_USER,
	"HKEY_CLASSES_ROOT": registry.CLASSES_ROOT, "HKCR": registry.CLASSES_ROOT,
	"HKEY_USERS": registry.USERS, "HKU": registry.USERS,
	"HKEY_CURRENT_CONFIG": registry.CURRENT_CONFIG, "HKCC": registry.CURRENT_CONFIG,
}

func evaluateRegistryRule(rule string) (bool, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rule), "r:"))

	parts := strings.SplitN(rest, " -> ", 3)
	keyPath := strings.TrimSpace(parts[0])

	rootName, sub, ok := strings.Cut(keyPath, `\`)
	if !ok {
		return false, false
	}
	root, ok := registryRoots[strings.ToUpper(strings.TrimSpace(rootName))]
	if !ok {
		return false, false
	}

	// WOW64 note: read the 64-bit view explicitly. A 32-bit read would be
	// silently redirected to Wow6432Node and report a different machine
	// than the one the benchmark is describing.
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return false, true // an absent key is a definite answer
	}
	defer k.Close()

	if len(parts) == 1 {
		return true, true // key exists, nothing more asked
	}
	valueName := strings.TrimSpace(parts[1])
	value, err := readRegistryValue(k, valueName)
	if err != nil {
		return false, true // absent value is a definite answer, not unknown
	}
	if len(parts) == 2 {
		return true, true // the value exists, which was the whole question
	}
	return applyMatcher(value, strings.TrimSpace(parts[2]))
}

// readRegistryValue renders any value type as the string a matcher will
// see. Numbers become decimal so an "n: … compare" matcher can read them.
func readRegistryValue(k registry.Key, name string) (string, error) {
	if s, _, err := k.GetStringValue(name); err == nil {
		return s, nil
	}
	if n, _, err := k.GetIntegerValue(name); err == nil {
		return strconv.FormatUint(n, 10), nil
	}
	if ss, _, err := k.GetStringsValue(name); err == nil {
		return strings.Join(ss, "\n"), nil
	}
	if b, _, err := k.GetBinaryValue(name); err == nil {
		return string(b), nil
	}
	_, _, err := k.GetValue(name, nil)
	return "", err
}
