package snapshot

import (
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strings"
)

var authKeyFiles = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}

func (c *collector) collectAuthorizedKeys() {
	seen := map[string]bool{}
	for _, u := range c.snap.Users {
		if u.Home == "" {
			continue
		}
		for _, rel := range authKeyFiles {
			logical := strings.TrimSuffix(u.Home, "/") + "/" + rel
			id := u.Name + "|" + logical
			if seen[id] {
				continue
			}
			seen[id] = true
			lines, err := readLines(c.host(logical))
			if err != nil {
				c.warnErr(logical, err)
				continue
			}
			for i, l := range lines {
				k, ok, err := ParseAuthorizedKey(l)
				if !ok {
					if err != "" {
						c.warn("%s line %d: %s", logical, i+1, err)
					}
					continue
				}
				k.User, k.File = u.Name, logical
				c.snap.AuthorizedKeys = append(c.snap.AuthorizedKeys, k)
			}
		}
	}
	sort.Slice(c.snap.AuthorizedKeys, func(i, j int) bool {
		a, b := c.snap.AuthorizedKeys[i], c.snap.AuthorizedKeys[j]
		if a.User != b.User {
			return a.User < b.User
		}
		return a.Fingerprint < b.Fingerprint
	})
}

// splitQuoted splits on whitespace but keeps double-quoted strings together.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\\' && inQ && i+1 < len(s):
			cur.WriteByte(ch)
			i++
			cur.WriteByte(s[i])
		case ch == '"':
			inQ = !inQ
			cur.WriteByte(ch)
		case (ch == ' ' || ch == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func isKeyType(t string) bool {
	return strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") ||
		strings.HasPrefix(t, "sk-ssh-") || strings.HasPrefix(t, "sk-ecdsa-")
}

// ParseAuthorizedKey parses one authorized_keys line. ok=false with an empty
// error string means "blank/comment line". Key material is hashed and dropped.
func ParseAuthorizedKey(line string) (k AuthKey, ok bool, errMsg string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return k, false, ""
	}
	toks := splitQuoted(line)
	idx := -1
	for i, t := range toks {
		if isKeyType(t) && i+1 < len(toks) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return k, false, "unrecognised key line"
	}
	blob, err := base64.StdEncoding.DecodeString(toks[idx+1])
	if err != nil || len(blob) == 0 {
		return k, false, "invalid base64 key data"
	}
	sum := sha256.Sum256(blob)
	k.Type = toks[idx]
	k.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	k.Options = strings.Join(toks[:idx], " ")
	k.Comment = strings.Join(toks[idx+2:], " ")
	return k, true, ""
}
