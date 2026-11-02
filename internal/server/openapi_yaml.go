package server

// The spec in YAML is converted from its JSON, token by token, rather
// than marshalled from the same map: the two documents then have the
// same keys in the same order, and every number keeps the literal
// encoding/json wrote. The output is YAML 1.2 within RFC 9512's
// interoperability profile, as OpenAPI recommends: string keys, no
// anchors, aliases or tags, so it reads back as the JSON document.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// jsonToYAML writes one JSON document as YAML.
func jsonToYAML(doc []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	root, err := yamlNode(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("more than one JSON value")
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// yamlNode reads the next JSON value from dec. A string is tagged as one,
// so the encoder quotes a value YAML 1.2 would otherwise read as something
// else ("true", "1.0", "null"); a number, boolean or null is left plain.
func yamlNode(dec *json.Decoder) (*yaml.Node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Delim:
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if v == '{' {
			node.Kind, node.Tag = yaml.MappingNode, "!!map"
		}
		for dec.More() {
			if node.Kind == yaml.MappingNode {
				key, err := dec.Token()
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content, yamlString(key.(string)))
			}
			child, err := yamlNode(dec)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, child)
		}
		if _, err := dec.Token(); err != nil { // the closing delimiter
			return nil, err
		}
		return node, nil
	case string:
		return yamlString(v), nil
	case json.Number:
		return &yaml.Node{Kind: yaml.ScalarNode, Value: v.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprint(v)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Value: "null"}, nil
	}
	return nil, fmt.Errorf("unexpected JSON token %v", tok)
}

// yamlString is a string scalar, double-quoted where a YAML 1.1 reader
// would take it as something else. Many tools still read YAML 1.1
// (PyYAML, SnakeYAML), where plain "off" is false and "22:00" is the
// sexagesimal number 1320, though both are strings in YAML 1.2.
func yamlString(s string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
	if yaml11Ambiguous(s) {
		n.Style = yaml.DoubleQuotedStyle
	}
	return n
}

// yaml11Ambiguous reports whether a plain s could be read by YAML 1.1 as
// other than a string: one of its boolean or null words, a merge or value
// key, or something starting like a number, time or date (a digit, sign
// or point). It errs on the side of quoting.
func yaml11Ambiguous(s string) bool {
	if s == "" || strings.ContainsRune("0123456789+-.", rune(s[0])) {
		return true
	}
	switch strings.ToLower(s) {
	case "y", "yes", "n", "no", "true", "false", "on", "off", "null", "~", "<<", "=":
		return true
	}
	return false
}
