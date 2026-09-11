package repo_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// maxCommentLines caps an implementation comment. Exported declarations, generated
// files, tool directives, and tagged blocks are exempt.
const maxCommentLines = 2

// commentExceptions mark a block whose length is the point: a constraint a reader
// cannot infer from the code.
func commentExceptions() []string {
	return []string{"SECURITY:", "CONCURRENCY:", "COMPAT:"}
}

// Go only: a hand-written scanner for shell, YAML and templates mistook `#` inside
// multiline strings for comments, so those languages are left to review.
func TestNewImplementationCommentsAreShort(t *testing.T) {
	t.Parallel()

	changed := changedLines(t)
	if len(changed) == 0 {
		t.Skip("no changed lines against the merge base")
	}

	for name, lines := range changed {
		if filepath.Ext(name) != ".go" {
			continue
		}

		content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // repository path
		if err != nil {
			continue
		}

		checkGoComments(t, name, content, lines)
	}
}

func checkGoComments(t *testing.T, name string, content []byte, changed map[int]bool) {
	t.Helper()

	positions := token.NewFileSet()

	file, err := parser.ParseFile(positions, name, content, parser.ParseComments)
	if err != nil {
		t.Errorf("parse %s: %v", name, err)

		return
	}

	if ast.IsGenerated(file) {
		return
	}

	documentation := exportedDocComments(file)

	for _, group := range file.Comments {
		if documentation[group] {
			continue
		}

		lines := proseCommentLines(group)
		if lines <= maxCommentLines {
			continue
		}

		span := commentSpan{
			line:   positions.Position(group.Pos()).Line,
			length: positions.Position(group.End()).Line - positions.Position(group.Pos()).Line + 1,
		}

		if !spanChanged(span, changed) || excepted(group.Text()) {
			continue
		}

		t.Errorf("%s: comment has %d lines; maximum is %d (%s)",
			positions.Position(group.Pos()), lines, maxCommentLines, exceptionHint())
	}
}

// exportedDocComments collects the doc comments that document the package or an
// exported declaration, including struct fields, which carry the CRD documentation.
func exportedDocComments(file *ast.File) map[*ast.CommentGroup]bool {
	exempt := map[*ast.CommentGroup]bool{file.Doc: true}

	ast.Inspect(file, func(node ast.Node) bool {
		documentation, exported := exportedDoc(node)
		if exported {
			exempt[documentation] = true
		}

		return true
	})

	delete(exempt, nil)

	return exempt
}

// exportedDoc returns a node's doc comment and whether it documents exported API.
func exportedDoc(node ast.Node) (*ast.CommentGroup, bool) {
	switch declaration := node.(type) {
	case *ast.FuncDecl:
		return declaration.Doc, declaration.Name.IsExported()
	case *ast.GenDecl:
		return declaration.Doc, slices.ContainsFunc(declaration.Specs, specExported)
	case *ast.TypeSpec:
		return declaration.Doc, declaration.Name.IsExported()
	case *ast.ValueSpec:
		return declaration.Doc, namesExported(declaration.Names)
	case *ast.Field:
		return declaration.Doc, namesExported(declaration.Names)
	}

	return nil, false
}

func namesExported(names []*ast.Ident) bool {
	for _, name := range names {
		if name.IsExported() {
			return true
		}
	}

	return false
}

func specExported(spec ast.Spec) bool {
	switch declaration := spec.(type) {
	case *ast.TypeSpec:
		return declaration.Name.IsExported()
	case *ast.ValueSpec:
		return namesExported(declaration.Names)
	}

	return false
}

// excepted matches a tag on any line, not just the first: a Go doc comment has to
// open with the declaration's name, so the tag marks the paragraph that earns the room.
func excepted(text string) bool {
	for line := range strings.SplitSeq(text, "\n") {
		trimmed := strings.TrimLeft(strings.TrimSpace(line), "/*{ ")

		for _, tag := range commentExceptions() {
			if strings.HasPrefix(trimmed, tag) {
				return true
			}
		}
	}

	return false
}

func exceptionHint() string {
	return "shorten it, move it to docs/, or open it with " + strings.Join(commentExceptions(), " / ")
}

func spanChanged(span commentSpan, changed map[int]bool) bool {
	for line := span.line; line < span.line+span.length; line++ {
		if changed[line] {
			return true
		}
	}

	return false
}

// changedLines maps each path to the lines this branch touched. It fails rather than
// skips when git cannot say, so a broken checkout does not disable the gate.
func changedLines(t *testing.T) map[string]map[int]bool {
	t.Helper()

	_, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git is not installed: %v", err)
	}

	base, ok := mergeBase(t)
	if !ok {
		t.Fatal("no merge base with origin/main or main; cannot tell which comments changed")
	}

	diff, ok := git(t, "diff", "-U0", "--no-color", base)
	if !ok {
		t.Fatalf("git diff against %s failed; cannot tell which comments changed", base)
	}

	changed := diffLines(diff)

	untracked, ok := git(t, "ls-files", "--others", "--exclude-standard")
	if !ok {
		t.Fatal("git ls-files failed; cannot tell which comments changed")
	}

	for name := range strings.SplitSeq(strings.TrimSpace(untracked), "\n") {
		if name != "" {
			changed[name] = everyLine(name)
		}
	}

	return changed
}

// diffLines reads the new-side line numbers out of a -U0 unified diff. A deletion-only
// hunk marks the lines around it, so trimming a comment still counts as touching it.
func diffLines(diff string) map[string]map[int]bool {
	changed := map[string]map[int]bool{}
	path := ""

	for line := range strings.SplitSeq(diff, "\n") {
		if after, found := strings.CutPrefix(line, "+++ b/"); found {
			path = after

			continue
		}

		if !strings.HasPrefix(line, "@@") || path == "" {
			continue
		}

		start, count := hunkRange(line)

		if changed[path] == nil {
			changed[path] = map[int]bool{}
		}

		if count == 0 {
			changed[path][max(start, 1)] = true
			changed[path][start+1] = true

			continue
		}

		for offset := range count {
			changed[path][start+offset] = true
		}
	}

	return changed
}

func everyLine(name string) map[int]bool {
	content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // repository path
	if err != nil {
		return nil
	}

	lines := map[int]bool{}
	for index := range strings.Count(string(content), "\n") + 1 {
		lines[index+1] = true
	}

	return lines
}

// hunkRange reads the new-side start and length from "@@ -a,b +c,d @@".
func hunkRange(header string) (int, int) {
	for field := range strings.FieldsSeq(header) {
		if !strings.HasPrefix(field, "+") {
			continue
		}

		start, count, found := strings.Cut(strings.TrimPrefix(field, "+"), ",")

		first, err := strconv.Atoi(start)
		if err != nil {
			return 0, 0
		}

		if !found {
			return first, 1
		}

		length, err := strconv.Atoi(count)
		if err != nil {
			return 0, 0
		}

		return first, length
	}

	return 0, 0
}

func mergeBase(t *testing.T) (string, bool) {
	t.Helper()

	for _, branch := range []string{"origin/main", "main"} {
		base, ok := git(t, "merge-base", "HEAD", branch)
		if ok {
			return strings.TrimSpace(base), true
		}
	}

	return "", false
}

func git(t *testing.T, args ...string) (string, bool) {
	t.Helper()

	bin, err := exec.LookPath("git")
	if err != nil {
		return "", false
	}

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	//nolint:gosec // git resolved through LookPath, with literal arguments
	out, err := exec.CommandContext(ctx, bin,
		append([]string{"-C", filepath.Join("..", "..")}, args...)...).Output()
	if err != nil {
		_, isExit := errors.AsType[*exec.ExitError](err)
		if !isExit {
			t.Fatalf("git %s: %v", strings.Join(args, " "), err)
		}

		return "", false
	}

	return string(out), true
}

type commentSpan struct {
	line   int
	length int
}

// Tool directives are metadata; they do not count toward the prose limit.
func proseCommentLines(group *ast.CommentGroup) int {
	var lines int

	for _, comment := range group.List {
		text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
		if strings.HasPrefix(text, "go:") || strings.HasPrefix(text, "nolint:") ||
			strings.HasPrefix(text, "+kubebuilder:") || text == "+optional" ||
			text == "+required" || strings.HasPrefix(text, "+k8s:") ||
			strings.HasPrefix(text, "+build ") || strings.HasPrefix(text, "line ") {
			continue
		}

		lines += strings.Count(comment.Text, "\n") + 1
	}

	return lines
}

func TestCommentCounting(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		code string
		want int
	}{
		{name: "two lines", code: "// First.\n// Second.\n", want: 2},
		{name: "blank line counts", code: "// First.\n//\n// Third.\n", want: 3},
		{name: "directives", code: "// First.\n// Second.\n// +optional\n//nolint:lll\n", want: 2},
		{name: "block", code: "/* First.\nSecond.\nThird. */\n", want: 3},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", test.code+"package fixture", parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}

			if got := proseCommentLines(file.Comments[0]); got != test.want {
				t.Errorf("comment lines = %d, want %d", got, test.want)
			}
		})
	}
}

func TestOnlyImplementationCommentsCount(t *testing.T) {
	t.Parallel()

	code := `package fixture

// Exported is documented across
// three lines
// of API documentation.
func Exported() {}

// unexported narrates across
// three lines
// of implementation detail.
func unexported() {}

// tagged does a thing.
//
// SECURITY: the tag earns the length, because
// this constraint is not inferable
// from the code below it.
func tagged() {}

type documented struct {
	// Field is documented across
	// three lines, as a CRD field is.
	// Kubernetes renders this.
	Field string

	// unexportedField narrates across
	// three lines of
	// implementation detail.
	unexportedField string
}
`

	positions := token.NewFileSet()

	file, err := parser.ParseFile(positions, "fixture.go", code, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	documentation := exportedDocComments(file)

	var flagged []int

	for _, group := range file.Comments {
		if documentation[group] || proseCommentLines(group) <= maxCommentLines || excepted(group.Text()) {
			continue
		}

		flagged = append(flagged, positions.Position(group.Pos()).Line)
	}

	if want := []int{8, 26}; !reflect.DeepEqual(flagged, want) {
		t.Errorf("flagged lines = %v, want %v", flagged, want)
	}
}

func TestExceptionTagIsFoundOnAnyLine(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"// name does a thing.\n//\n// SECURITY: and this is why it is long.": true,
		"/* CONCURRENCY: the lock order matters here. */":                     true,
		"// name does a thing.\n// It is simply verbose about it.":            false,
		"// the word security appears but not as a tag":                       false,
	}
	for text, want := range cases {
		t.Run(text, func(t *testing.T) {
			t.Parallel()

			if got := excepted(text); got != want {
				t.Errorf("excepted(%q) = %v, want %v", text, got, want)
			}
		})
	}
}

func TestHunkRange(t *testing.T) {
	t.Parallel()

	cases := map[string][2]int{
		"@@ -1,0 +2,3 @@":          {2, 3},
		"@@ -4 +7 @@":              {7, 1},
		"@@ -1,2 +1,2 @@ func x()": {1, 2},
		"@@ -30,1 +29,0 @@":        {29, 0},
	}
	for header, want := range cases {
		t.Run(header, func(t *testing.T) {
			t.Parallel()

			start, count := hunkRange(header)
			if start != want[0] || count != want[1] {
				t.Errorf("hunkRange(%q) = %d,%d, want %d,%d", header, start, count, want[0], want[1])
			}
		})
	}
}

// A deletion-only hunk has no new-side lines, so the surrounding ones stand in: cutting
// a four-line comment to three still has to be caught.
func TestDeletionOnlyHunksMarkTheirSurroundings(t *testing.T) {
	t.Parallel()

	diff := "+++ b/agent/x.go\n@@ -30,1 +29,0 @@\n-// a deleted comment line\n"

	changed := diffLines(diff)
	if !changed["agent/x.go"][29] || !changed["agent/x.go"][30] {
		t.Errorf("deletion at 29 marked %v", changed["agent/x.go"])
	}

	if !spanChanged(commentSpan{line: 27, length: 3}, changed["agent/x.go"]) {
		t.Error("a comment left behind by a deletion was treated as untouched")
	}
}
