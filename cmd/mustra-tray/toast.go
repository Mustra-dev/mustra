package main

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// The toast document Windows renders.
//
// It is built with encoding/xml rather than by pasting strings together,
// because every field in it is operator-written text and one unescaped
// quote in a button label would otherwise produce a toast that silently
// never appears. Kept out of the Windows-only file so the shape can be
// tested on any machine -- the rendering needs Windows, the document does
// not.

type toastXML struct {
	XMLName        xml.Name `xml:"toast"`
	ActivationType string   `xml:"activationType,attr,omitempty"`
	Launch         string   `xml:"launch,attr,omitempty"`
	Duration       string   `xml:"duration,attr,omitempty"`
	Scenario       string   `xml:"scenario,attr,omitempty"`
	Visual         toastVisual
	Actions        *toastActions `xml:"actions,omitempty"`
}

type toastVisual struct {
	XMLName xml.Name     `xml:"visual"`
	Binding toastBinding `xml:"binding"`
}

type toastBinding struct {
	Template string       `xml:"template,attr"`
	Images   []toastImage `xml:"image,omitempty"`
	Texts    []string     `xml:"text"`
}

type toastImage struct {
	Placement string `xml:"placement,attr,omitempty"`
	Src       string `xml:"src,attr"`
	HintCrop  string `xml:"hint-crop,attr,omitempty"`
}

type toastActions struct {
	XMLName xml.Name      `xml:"actions"`
	Actions []toastAction `xml:"action"`
}

type toastAction struct {
	Content        string `xml:"content,attr"`
	ActivationType string `xml:"activationType,attr"`
	Arguments      string `xml:"arguments,attr"`
	HintButtonSty  string `xml:"hint-buttonStyle,attr,omitempty"`
}

// buildToastXML turns a notification into the document Windows renders.
func buildToastXML(n *notification, logoPath string) (string, error) {
	binding := toastBinding{Template: "ToastGeneric", Texts: []string{n.Title}}
	if n.Body != "" {
		binding.Texts = append(binding.Texts, n.Body)
	}
	// A deadline is the one piece of context that changes what a person
	// does about a message, so it goes on the toast rather than only in the
	// window they might not open.
	if n.MinutesLeft != nil && *n.MinutesLeft > 0 {
		binding.Texts = append(binding.Texts, fmt.Sprintf("Expires in %d minute(s).", *n.MinutesLeft))
	}
	if logoPath != "" {
		// Not filepath.ToSlash: that is a no-op when the host separator is
		// already "/", so the URI this produced depended on which machine
		// built the binary rather than on the path being described. The
		// path is always a Windows one.
		binding.Images = append(binding.Images, toastImage{
			Placement: "appLogoOverride", Src: "file:///" + strings.ReplaceAll(logoPath, `\`, "/"),
		})
	}

	doc := toastXML{
		ActivationType: "protocol",
		Launch:         protocolScheme + "://open",
		Visual:         toastVisual{Binding: binding},
	}
	// A restart negotiation should not fade away while somebody is at
	// lunch; a notice should. reminder keeps it on screen until it is
	// answered, which is the behaviour the Self Service window already has.
	if n.Kind == "restart" {
		doc.Duration, doc.Scenario = "long", "reminder"
	}

	if choices := n.choices(); len(choices) > 0 {
		acts := &toastActions{}
		// Windows renders at most five buttons on a toast and silently
		// drops the toast entirely if given more, so the cap is not
		// cosmetic.
		for i, b := range choices {
			if i >= 5 {
				break
			}
			a := toastAction{
				Content: b.Label, ActivationType: "protocol", Arguments: b.activationURI(),
			}
			if b.Action == "restart_now" {
				// Marks the destructive choice, so "Restart now" does not
				// look like the safe default.
				a.HintButtonSty = "Critical"
			}
			acts.Actions = append(acts.Actions, a)
		}
		doc.Actions = acts
	}

	out, err := xml.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
