package sudors

// Links to the primary sources each rule is based on. Source code links are
// pinned to the release Ubuntu 26.04 is based on (v0.2.13) so line numbers
// stay valid.
const (
	repo         = "https://github.com/trifectatechfoundation/sudo-rs"
	srcReadme    = repo + "/blob/v0.2.15/README.md#differences-from-original-sudo"
	srcFAQ       = repo + "/blob/v0.2.15/FAQ.md#why-did-you-change-x"
	srcManWild   = repo + "/blob/v0.2.13/docs/man/sudoers.5.md#wildcards"
	srcManIncl   = repo + "/blob/v0.2.13/docs/man/sudoers.5.md#including-other-files-from-within-sudoers"
	srcManCmnd   = repo + "/blob/v0.2.13/docs/man/sudoers.5.md#aliases"
	srcArgs      = repo + "/blob/v0.2.13/src/sudoers/tokens.rs#L196-L228"
	srcRegex     = repo + "/blob/v0.2.13/src/sudoers/tokens.rs#L200-L208"
	srcDigest    = repo + "/blob/v0.2.13/src/sudoers/tokens.rs#L267"
	srcArgMatch  = repo + "/blob/v0.2.13/src/sudoers/mod.rs#L643-L644"
	srcIPv4      = repo + "/blob/v0.2.13/src/sudoers/tokens.rs#L80-L101"
	srcNetgroup  = repo + "/blob/v0.2.13/src/sudoers/ast.rs#L256-L258"
	srcNonunix   = repo + "/blob/v0.2.13/src/sudoers/mod.rs#L594-L598"
	srcTags      = repo + "/blob/v0.2.13/src/sudoers/ast.rs#L350-L371"
	srcTagWarn   = repo + "/blob/v0.2.13/src/sudoers/mod.rs#L754-L758"
	srcDefaults  = repo + "/blob/v0.2.13/src/defaults/mod.rs#L30-L82"
	srcDefParse  = repo + "/blob/v0.2.13/src/sudoers/ast.rs#L736-L822"
	srcInclH     = repo + "/blob/v0.2.13/src/sudoers/mod.rs#L795-L804"
	srcSudoersR  = repo + "/blob/v0.2.13/src/sudo/mod.rs#L49-L62"
	srcContinue  = repo + "/commit/7780f59392adeed49a0f4c60a2e15ec05f70c398"
	srcTab       = repo + "/commit/4df2904d960505a77e4166d0d4813cdbc7ed78ac"
	srcUserSpace = repo + "/commit/474e1b51c041045b7693ee79ca339d8ce90665d2"
	srcUbuntu    = "https://ubuntu.com/server/docs/reference/other-tools/sudo-rs/"
	srcUSN       = "https://ubuntu.com/security/notices/USN-8708-1"
)
