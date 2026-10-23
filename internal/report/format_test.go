package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/permdrift/permdrift/internal/diff"
)

func TestWriteJSONSchema(t *testing.T) {
	in := input(t)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, in); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	for _, k := range []string{"version", "tool", "tool_version", "base", "current", "ignored", "summary", "changes"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("missing top-level key %q", k)
		}
	}
	var v struct {
		Version int `json:"version"`
		Tool    string
		Summary struct {
			Total, High, Medium, Low int
			ByCategory               map[string]int `json:"by_category"`
		}
		Changes []map[string]any
		Base    struct{ Hostname string }
	}
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Version != JSONVersion || v.Tool != "permdrift" {
		t.Errorf("version/tool = %d/%q", v.Version, v.Tool)
	}
	if v.Summary.Total != len(in.Changes) || v.Summary.Total != len(v.Changes) || v.Summary.Total == 0 {
		t.Errorf("summary total %d, changes %d, want %d", v.Summary.Total, len(v.Changes), len(in.Changes))
	}
	if v.Summary.High+v.Summary.Medium+v.Summary.Low != v.Summary.Total {
		t.Errorf("severity counts do not add up: %+v", v.Summary)
	}
	if v.Base.Hostname != "demo-host" {
		t.Errorf("base hostname = %q", v.Base.Hostname)
	}
	for _, k := range []string{"type", "category", "subject", "severity", "message"} {
		if _, ok := v.Changes[0][k]; !ok {
			t.Errorf("change missing %q", k)
		}
	}
	if s, _ := v.Changes[0]["severity"].(string); s != "High" && s != "Medium" && s != "Low" {
		t.Errorf("severity should be a word, got %v", v.Changes[0]["severity"])
	}
}

func TestWriteJSONStableAndEmptyList(t *testing.T) {
	in := input(t)
	var a, b bytes.Buffer
	WriteJSON(&a, in)
	WriteJSON(&b, in)
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("JSON output is not deterministic")
	}
	in.Changes = nil
	a.Reset()
	if err := WriteJSON(&a, in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.String(), `"changes": []`) || strings.Contains(a.String(), "null") {
		t.Errorf("empty diff should give an empty list and no null:\n%s", a.String())
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		"":          "",
		"plain":     "plain",
		"=1+1":      "'=1+1",
		"+cmd":      "'+cmd",
		"-2":        "'-2",
		"@SUM(A1)":  "'@SUM(A1)",
		"\tx":       "'\tx",
		"\rx":       "'\rx",
		"a=b":       "a=b",
		" =spaced":  " =spaced",
		"'=already": "'=already",
	} {
		if got := CSVSafe(in); got != want {
			t.Errorf("CSVSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteCSV(t *testing.T) {
	in := input(t)
	in.Changes = []diff.Change{
		{Type: diff.Added, Category: "user", Subject: "=HYPERLINK(\"http://x\")", Severity: diff.High, Message: "=cmd|' /C calc'!A0"},
		{Type: diff.Changed, Category: "suid", Subject: "/usr/bin/a,b", Severity: diff.Low, Message: "has \"quotes\", commas\nand a newline"},
		{Type: diff.Removed, Category: "x", Subject: "-1+1", Severity: diff.Medium, Message: "@evil"},
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, in); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid csv: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("want header + 3 rows, got %d", len(rows))
	}
	if strings.Join(rows[0], ",") != "severity,type,category,subject,message" {
		t.Errorf("header = %v", rows[0])
	}
	if rows[1][3] != "'=HYPERLINK(\"http://x\")" || rows[1][4] != "'=cmd|' /C calc'!A0" {
		t.Errorf("row 1 = %q", rows[1])
	}
	if rows[2][3] != "/usr/bin/a,b" || rows[2][4] != "has \"quotes\", commas\nand a newline" {
		t.Errorf("escaping broke the data: %q", rows[2])
	}
	if rows[3][3] != "'-1+1" || rows[3][4] != "'@evil" {
		t.Errorf("row 3 = %q", rows[3])
	}
	for _, r := range rows[1:] {
		for _, c := range r {
			if c != "" && strings.ContainsRune("=+-@", rune(c[0])) {
				t.Errorf("cell %q starts with a formula character", c)
			}
		}
	}
}

func TestWriteCSVNoChanges(t *testing.T) {
	in := input(t)
	in.Changes = nil
	var buf bytes.Buffer
	if err := WriteCSV(&buf, in); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "severity,type,category,subject,message\n" {
		t.Errorf("got %q", buf.String())
	}
}

func TestWriteDispatch(t *testing.T) {
	in := input(t)
	for _, f := range []string{"", "text", "json", "csv"} {
		var buf bytes.Buffer
		if err := Write(&buf, f, in); err != nil || buf.Len() == 0 {
			t.Errorf("format %q: err=%v len=%d", f, err, buf.Len())
		}
	}
	if err := Write(&bytes.Buffer{}, "xml", in); err == nil {
		t.Error("unknown format should fail")
	}
	if !ValidFormat("csv") || ValidFormat("xml") {
		t.Error("ValidFormat wrong")
	}
}
