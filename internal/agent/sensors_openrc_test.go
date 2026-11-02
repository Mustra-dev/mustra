package agent

import (
	"reflect"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestParseRCStatus(t *testing.T) {
	out := "Runlevel: default\n tvrelay-wol                                                       [  started  ]\n" +
		" mustra-agent                                     [  started 00:01:02 (0) ]\n" +
		"Dynamic Runlevel: hotplugged\nDynamic Runlevel: needed/wanted\n localmount                                    [  started  ]\n" +
		"Runlevel: boot\n localmount                                    [  started  ]\n cgroups                                       [  stopped  ]\n"
	want := []proto.ServiceInfo{{Name: "tvrelay-wol", Status: "started"}, {Name: "mustra-agent", Status: "started 00:01:02 (0)"},
		{Name: "localmount", Status: "started"}, {Name: "cgroups", Status: "stopped"}}
	if got := parseRCStatus(out); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}
