package server

import (
	"fmt"
	"regexp"
)

// clientObjectID is the shape an ID chosen by an API client may take.
// Policies, playbooks, reports and their steps and sections keep whatever
// ID a save request names, so the ID is operator-controlled text that the
// console later writes into attributes and URLs. Server-minted IDs
// (idgen.New) are a prefix plus hex and always match; anything with quotes,
// angle brackets, spaces or slashes is refused rather than stored.
var clientObjectID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// checkClientID reports an error for a non-empty ID that doesn't have the
// shape above. An empty ID means "mint one".
func checkClientID(what, id string) error {
	if id == "" || clientObjectID.MatchString(id) {
		return nil
	}
	return fmt.Errorf("%s id may use only letters, digits, '.', ':', '_' and '-' (at most 128)", what)
}
