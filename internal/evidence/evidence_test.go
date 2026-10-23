package evidence

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/permdrift/permdrift/internal/diff"
	"github.com/permdrift/permdrift/internal/fixture"
	"github.com/permdrift/permdrift/internal/report"
	"github.com/permdrift/permdrift/internal/snapshot"
)

var fixedNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func testInput(t *testing.T) Input {
	t.Helper()
	root := t.TempDir()
	fixture.Base(t, root)
	base, err := snapshot.Collect(snapshot.Options{Root: root, ToolVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	fixture.Drift(t, root)
	cur, err := snapshot.Collect(snapshot.Options{Root: root, ToolVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		Report:     report.Input{Base: base, Current: cur, Changes: diff.Compare(base, cur), ToolVersion: "9.9.9"},
		BaseRaw:    []byte(`{"raw":"base"}`),
		CurrentRaw: []byte(`{"raw":"current"}`),
		BaseName:   "base.json", CurName: "now.json",
		MinSev: diff.Low, Now: fixedNow,
	}
}

func byName(files []File) map[string][]byte {
	m := map[string][]byte{}
	for _, f := range files {
		m[f.Name] = f.Data
	}
	return m
}

func TestBuildFiles(t *testing.T) {
	in := testInput(t)
	files, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	m := byName(files)
	for _, n := range []string{BaseFile, CurrentFile, DiffText, DiffJSON, HTMLFile, ReviewFile, MetadataFile, ManifestFile} {
		if len(m[n]) == 0 {
			t.Errorf("missing or empty %s", n)
		}
	}
	if len(files) != 8 {
		t.Errorf("want 8 files, got %d", len(files))
	}
	if string(m[BaseFile]) != string(in.BaseRaw) || string(m[CurrentFile]) != string(in.CurrentRaw) {
		t.Error("inputs must be copied byte for byte")
	}
	if !strings.Contains(string(m[DiffText]), "DRIFT DETECTED") {
		t.Error("diff.txt should hold the text diff")
	}
	var dj map[string]any
	if err := json.Unmarshal(m[DiffJSON], &dj); err != nil || dj["version"] == nil {
		t.Errorf("diff.json invalid: %v", err)
	}
	if !strings.Contains(string(m[HTMLFile]), "2026-10-23T12:00:00Z") {
		t.Error("report.html should carry the bundle time")
	}
}

func TestMetadata(t *testing.T) {
	in := testInput(t)
	in.IgnoreFile = "ign.txt"
	in.Report.Ignored = 3
	files, _ := Build(in)
	var md Metadata
	if err := json.Unmarshal(byName(files)[MetadataFile], &md); err != nil {
		t.Fatal(err)
	}
	if md.ToolVersion != "9.9.9" || md.GeneratedAt != "2026-10-23T12:00:00Z" || md.Version != MetadataVersion {
		t.Errorf("metadata = %+v", md)
	}
	if md.Base.InputName != "base.json" || md.Current.InputName != "now.json" || md.Current.Hostname != "demo-host" {
		t.Errorf("snapshot info = %+v / %+v", md.Base, md.Current)
	}
	if md.Base.ContentHash == "" || md.Current.Timestamp == "" || md.IgnoreFile != "ign.txt" || md.Ignored != 3 || md.MinSeverity != "low" {
		t.Errorf("metadata = %+v", md)
	}
	if md.Total == 0 || md.High == 0 || md.Total != md.High+md.Medium+md.Low {
		t.Errorf("counts = %+v", md)
	}
	if !strings.Contains(md.Note, "Not a signature") {
		t.Error("note should say this is not a signature")
	}
}

func TestManifestCoversEveryFileAndVerifies(t *testing.T) {
	files, _ := Build(testInput(t))
	m := byName(files)
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(m[ManifestFile])))
	for sc.Scan() {
		hash, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("bad manifest line %q", sc.Text())
		}
		sum := sha256.Sum256(m[name])
		if hex.EncodeToString(sum[:]) != hash {
			t.Errorf("hash mismatch for %s", name)
		}
		seen[name] = true
	}
	for _, f := range files {
		if f.Name == ManifestFile {
			if seen[f.Name] {
				t.Error("manifest must not list itself")
			}
		} else if !seen[f.Name] {
			t.Errorf("manifest misses %s", f.Name)
		}
	}
}

func TestReviewTemplate(t *testing.T) {
	in := testInput(t)
	r := Review(in.Report, fixedNow)
	sum := diff.Summarize(in.Report.Changes)
	if got := strings.Count(r, "### H"); got != sum.High {
		t.Errorf("want %d High entries, got %d", sum.High, got)
	}
	if strings.Count(r, "[ ] approved  [ ] not approved") != sum.High {
		t.Error("each High finding needs a decision line")
	}
	for _, w := range []string{"Reviewer name:", "Review date:", "Notes:", "Nothing in this bundle is signed"} {
		if !strings.Contains(r, w) {
			t.Errorf("review missing %q", w)
		}
	}
	// medium and low findings are not listed one by one
	for _, c := range in.Report.Changes {
		if c.Severity != diff.High && strings.Contains(r, c.Message) {
			t.Errorf("non-high finding listed: %s", c.Message)
		}
	}
	in.Report.Changes = nil
	if r := Review(in.Report, fixedNow); !strings.Contains(r, "No high findings") || strings.Contains(r, "### H") {
		t.Error("empty diff should say there are no high findings")
	}
}

func TestReviewEscapesHostileText(t *testing.T) {
	in := testInput(t)
	in.Report.Current.Hostname = "<script>alert(1)</script>"
	in.Report.Changes = []diff.Change{{Type: diff.Added, Category: "user", Subject: "x", Severity: diff.High,
		Message: "user <script>alert(2)</script> [x](http://evil) `code`\x1b[2J\nINJECTED"}}
	r := Review(in.Report, fixedNow)
	for _, bad := range []string{"<script", "\x1b", "[x](", "`code`", "\nINJECTED"} {
		if strings.Contains(r, bad) {
			t.Errorf("review contains unescaped %q:\n%s", bad, r)
		}
	}
}

func TestHostileHostnameInHTML(t *testing.T) {
	in := testInput(t)
	in.Report.Current.Hostname = "<script>alert(1)</script>"
	files, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if h := string(byName(files)[HTMLFile]); strings.Contains(h, "<script") {
		t.Error("hostname not escaped in report.html")
	}
}

func TestSafeNameAndDefaultName(t *testing.T) {
	for in, want := range map[string]string{
		"web-01.example.com":     "web-01.example.com",
		"../../etc/passwd":       "_._etc_passwd",
		"a b/c\\d":               "a_b_c_d",
		"<script>":               "_script_",
		"":                       "unknown",
		"...":                    "unknown",
		strings.Repeat("a", 100): strings.Repeat("a", 64),
	} {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := DefaultName("web1", fixedNow); got != "evidence-web1-2026-10-23.zip" {
		t.Errorf("DefaultName = %q", got)
	}
}

func TestWriteZip(t *testing.T) {
	files, _ := Build(testInput(t))
	dir := t.TempDir()
	p := filepath.Join(dir, "evidence-demo-host-2026-10-23.zip")
	if err := WriteZip(p, files, fixedNow, false); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	want := byName(files)
	if len(zr.File) != len(files) {
		t.Fatalf("zip has %d entries, want %d", len(zr.File), len(files))
	}
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "evidence-demo-host-2026-10-23/") || strings.Contains(f.Name, "..") {
			t.Errorf("unexpected entry name %q", f.Name)
		}
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if string(b) != string(want[strings.TrimPrefix(f.Name, "evidence-demo-host-2026-10-23/")]) {
			t.Errorf("content of %s differs", f.Name)
		}
	}
	// no temp files left behind
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("leftover files in output dir: %v", ents)
	}
	// existing file is protected unless forced
	if err := WriteZip(p, files, fixedNow, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected refusal, got %v", err)
	}
	if err := WriteZip(p, files, fixedNow, true); err != nil {
		t.Errorf("force should replace: %v", err)
	}
	if err := WriteZip(filepath.Join(dir, "no-such-dir", "x.zip"), files, fixedNow, false); err == nil {
		t.Error("missing output directory should fail")
	}
}

func TestWriteDir(t *testing.T) {
	files, _ := Build(testInput(t))
	d := filepath.Join(t.TempDir(), "bundle")
	if err := WriteDir(d, files); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(d, f.Name))
		if err != nil || string(b) != string(f.Data) {
			t.Errorf("%s: err=%v", f.Name, err)
		}
	}
	if err := WriteDir(d, files); err == nil {
		t.Error("non-empty directory should be refused")
	}
	empty := t.TempDir()
	if err := WriteDir(empty, files); err != nil {
		t.Errorf("empty existing dir should work: %v", err)
	}
}

func TestBuildNeedsSnapshots(t *testing.T) {
	if _, err := Build(Input{}); err == nil {
		t.Error("expected error")
	}
}
