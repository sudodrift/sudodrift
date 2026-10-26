package sudors

// The tables in this file come from the defaults! block in sudo-rs
// src/defaults/mod.rs at the tags v0.2.8, v0.2.13 and v0.2.15, plus the
// "Differences from original sudo" list in the sudo-rs README. See
// docs/sudo-rs.md for links.

type settingKind int

const (
	kindFlag settingKind = iota
	kindInt
	kindText
	kindList
	kindEnum
)

type setting struct {
	kind      settingKind
	negatable bool     // "!name" is accepted
	values    []string // allowed values for kindEnum
	min, max  int      // range for kindInt when max > 0
	since     version  // first sudo-rs release that knows the name
	until     version  // last release with this definition (zero means still current)
	ignored   bool     // parsed but has no effect in sudo-rs
}

var (
	v028  = version{0, 2, 8}
	v0212 = version{0, 2, 12}
	v0213 = version{0, 2, 13}
	v0214 = version{0, 2, 14}
	v0215 = version{0, 2, 15}
)

// settings lists every Defaults name sudo-rs accepts. A name can appear more
// than once when its type changed between releases.
var settings = map[string][]setting{
	"always_query_group_plugin": {{kind: kindFlag, negatable: true, since: v028, ignored: true}},
	"always_set_home":           {{kind: kindFlag, negatable: true, since: v028, ignored: true}},
	"env_reset":                 {{kind: kindFlag, negatable: true, since: v028, ignored: true}},
	"fqdn":                      {{kind: kindFlag, negatable: true, since: v028, ignored: true}},
	"ignore_dot":                {{kind: kindFlag, negatable: true, since: v028, ignored: true}},
	"lecture": {
		{kind: kindFlag, negatable: true, since: v028, until: v0212, ignored: true},
		{kind: kindEnum, negatable: true, values: []string{"always", "once", "never"}, since: v0213, ignored: true},
	},
	"mailerpath":          {{kind: kindText, negatable: true, since: v028, ignored: true}},
	"mail_badpass":        {{kind: kindFlag, negatable: true, since: v028, ignored: true}},
	"match_group_by_gid":  {{kind: kindFlag, negatable: true, since: v028, ignored: true}},
	"use_pty":             {{kind: kindFlag, negatable: true, since: v028}},
	"visiblepw":           {{kind: kindFlag, negatable: true, since: v028, ignored: true}},
	"pwfeedback":          {{kind: kindFlag, negatable: true, since: v028}},
	"rootpw":              {{kind: kindFlag, negatable: true, since: v028}},
	"targetpw":            {{kind: kindFlag, negatable: true, since: v028}},
	"noexec":              {{kind: kindFlag, negatable: true, since: v028}},
	"noninteractive_auth": {{kind: kindFlag, negatable: true, since: version{0, 2, 9}}},
	"log_allowed":         {{kind: kindFlag, negatable: true, since: v0215}},
	"log_denied":          {{kind: kindFlag, negatable: true, since: v0215, ignored: true}},
	"insults":             {{kind: kindFlag, negatable: true, since: v028, ignored: true}},
	"setenv":              {{kind: kindFlag, negatable: true, since: v028}},
	"runcwd":              {{kind: kindText, negatable: true, since: v0214}},
	"apparmor_profile":    {{kind: kindText, negatable: true, since: v028}},
	"umask":               {{kind: kindInt, negatable: true, since: v028}},
	"umask_override":      {{kind: kindFlag, negatable: true, since: v028}},
	"passwd_tries":        {{kind: kindInt, min: 0, max: 1000, since: v028}},
	"secure_path":         {{kind: kindText, negatable: true, since: v028}},
	"verifypw":            {{kind: kindEnum, negatable: true, values: []string{"all", "always", "any", "never"}, since: v028, ignored: true}},
	"passwd_timeout":      {{kind: kindInt, negatable: true, since: v028}},
	"timestamp_timeout":   {{kind: kindInt, negatable: true, since: v028}},
	"timestamp_type":      {{kind: kindEnum, values: []string{"tty", "ppid"}, since: v0215}},
	"editor":              {{kind: kindText, since: v028}},
	"env_editor":          {{kind: kindFlag, negatable: true, since: v028}},
	"env_keep":            {{kind: kindList, negatable: true, since: v028}},
	"env_check":           {{kind: kindList, negatable: true, since: v028}},
	"env_delete":          {{kind: kindList, negatable: true, since: v028, ignored: true}},
}

// lookupSetting returns the definition of name for sudo-rs release v.
func lookupSetting(name string, v version) (setting, bool) {
	for _, s := range settings[name] {
		if v.less(s.since) {
			continue
		}
		if s.until != (version{}) && s.until.less(v) {
			continue
		}
		return s, true
	}
	return setting{}, false
}

// firstRelease returns the first release that knows name, if any.
func firstRelease(name string) (version, bool) {
	defs, ok := settings[name]
	if !ok {
		return version{}, false
	}
	return defs[0].since, true
}

// unknownNotes explains well-known original sudo options that sudo-rs does
// not have. Anything not listed gets a generic message.
var unknownNotes = map[string]string{
	"requiretty":        "sudo-rs does not implement requiretty on purpose (sudo-rs FAQ, \"Why did you change X?\").",
	"logfile":           "sudo-rs always logs to syslog and has no logfile option (sudo-rs README).",
	"sudoedit_checkdir": "sudo-rs always behaves as if sudoedit_checkdir is on (sudo-rs README).",
	"sudoedit_follow":   "sudo-rs always behaves as if sudoedit_follow is off (sudo-rs README).",
	"log_input":         "sudo-rs has no I/O logging (Ubuntu sudo-rs docs: I/O logging and sudoreplay are not supported).",
	"log_output":        "sudo-rs has no I/O logging (Ubuntu sudo-rs docs: I/O logging and sudoreplay are not supported).",
	"iolog_dir":         "sudo-rs has no I/O logging (Ubuntu sudo-rs docs: I/O logging and sudoreplay are not supported).",
	"iolog_file":        "sudo-rs has no I/O logging (Ubuntu sudo-rs docs: I/O logging and sudoreplay are not supported).",
	"mailto":            "sudo-rs does not send mail (sudo-rs README).",
	"mail_always":       "sudo-rs does not send mail (sudo-rs README).",
	"mail_no_user":      "sudo-rs does not send mail (sudo-rs README).",
	"mail_no_perms":     "sudo-rs does not send mail (sudo-rs README).",
	"intercept":         "sudo-rs does not support INTERCEPT (sudo-rs README).",
	"passprompt":        "sudo-rs prints its own prompt, \"[sudo: authenticate] <PAM prompt>\" (Ubuntu sudo-rs docs).",
}
