package ignore

import (
	"strings"
	"testing"
)

func TestMatcher(t *testing.T) {
	m, err := Parse(strings.NewReader(`
# comment
ignore:
- "suid:/usr/bin/sudo"
ssh_key:deploy:*
/usr/lib/*   # trailing comment
user:build?
`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Len() != 4 {
		t.Fatalf("patterns = %d, want 4", m.Len())
	}
	cases := []struct {
		cat, subj string
		want      bool
	}{
		{"suid", "/usr/bin/sudo", true},
		{"suid", "/usr/bin/su", false},
		{"ssh_key", "deploy:SHA256:abc", true},
		{"ssh_key", "bob:SHA256:abc", false},
		{"world_writable", "/usr/lib/x/y", true},
		{"user", "build1", true},
		{"user", "build12", false},
	}
	for _, c := range cases {
		if got := m.Match(c.cat, c.subj); got != c.want {
			t.Errorf("Match(%s,%s)=%v want %v", c.cat, c.subj, got, c.want)
		}
	}
	var nilM *Matcher
	if nilM.Match("a", "b") {
		t.Error("nil matcher must not match")
	}
}
