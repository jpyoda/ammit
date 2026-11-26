// Package collect loads an add-on from disk into an ir.Artifact.
//
// The collector only reads. It never executes anything, never follows
// symlinks, and enforces size limits so a hostile add-on cannot exhaust
// memory. Archive expansion happens later, in the normalizer.
package collect

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/jpyoda/ammit/internal/ir"
)

// Limits bounds how much the collector and normalizer will read.
type Limits struct {
	MaxFiles      int   // files per artifact, including extracted ones
	MaxFileBytes  int64 // bytes read per file
	MaxTotalBytes int64 // bytes across the artifact, including extracted
	MaxDepth      int   // nested archive depth
}

// DefaultLimits are generous for real add-ons and small enough to stop
// archive bombs.
var DefaultLimits = Limits{
	MaxFiles:      5000,
	MaxFileBytes:  20 << 20,
	MaxTotalBytes: 200 << 20,
	MaxDepth:      3,
}

// skipDir reports directories that are never descended into. Only git's
// compressed object store is skipped: everything else, including
// node_modules and .git/hooks, can hide a payload and is scanned.
func skipDir(p string) bool {
	return filepath.Base(p) == "objects" && filepath.Base(filepath.Dir(p)) == ".git"
}

// Load reads path (a directory, an archive, or a single file).
func Load(path string, lim Limits) (*ir.Artifact, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	a := ir.New(filepath.Base(abs), abs)
	var total int64

	addFile := func(rel, full string, fi fs.FileInfo) {
		if len(a.Files) >= lim.MaxFiles {
			return
		}
		f := &ir.File{Path: filepath.ToSlash(rel), Size: fi.Size()}
		data, truncated, rerr := readLimited(full, lim.MaxFileBytes)
		if rerr != nil {
			a.AddNote("unreadable", fmt.Sprintf("%s: %v", rel, rerr))
			return
		}
		total += int64(len(data))
		f.Raw = data
		f.Kind = Classify(rel, data)
		if truncated {
			f.AddNote("truncated", 0, fmt.Sprintf("file is %d bytes; only the first %d were analyzed", fi.Size(), lim.MaxFileBytes))
		}
		if f.Kind.IsText() {
			f.Text = string(data)
		}
		a.Add(f)
	}

	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("%s is a symlink; refusing to follow it", path)
	case info.IsDir():
		err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				a.AddNote("unreadable", werr.Error())
				return nil
			}
			rel, _ := filepath.Rel(abs, p)
			if d.IsDir() {
				if p != abs && skipDir(p) {
					return filepath.SkipDir
				}
				return nil
			}
			fi, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			if fi.Mode()&fs.ModeSymlink != 0 {
				target, _ := os.Readlink(p)
				a.AddNote("symlink", fmt.Sprintf("%s -> %s (not followed)", filepath.ToSlash(rel), target))
				return nil
			}
			if !fi.Mode().IsRegular() {
				return nil
			}
			if len(a.Files) >= lim.MaxFiles {
				a.AddNote("limit", fmt.Sprintf("stopped after %d files", lim.MaxFiles))
				return filepath.SkipAll
			}
			if total >= lim.MaxTotalBytes {
				a.AddNote("limit", fmt.Sprintf("stopped after %d bytes", lim.MaxTotalBytes))
				return filepath.SkipAll
			}
			addFile(rel, p, fi)
			return nil
		})
		if err != nil {
			return nil, err
		}
	default:
		addFile(filepath.Base(abs), abs, info)
	}
	a.Kind = DetectKind(a)
	return a, nil
}

func readLimited(path string, max int64) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}

var (
	markdownExt = set(".md", ".markdown", ".mdc", ".mdx", ".rst")
	scriptExt   = set(".py", ".sh", ".bash", ".zsh", ".fish", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
		".rb", ".pl", ".ps1", ".psm1", ".bat", ".cmd", ".go", ".rs", ".php", ".lua", ".swift", ".applescript", ".scpt")
	configExt   = set(".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".npmrc", ".pypirc", ".plist", ".xml")
	compiledExt = set(".pyc", ".pyo", ".class", ".wasm", ".pkl", ".pickle")
	archiveExt  = set(".zip", ".skill", ".whl", ".jar", ".tar", ".tgz", ".gz", ".vsix")
	documentExt = set(".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")
	dataExt     = set(".ttf", ".otf", ".woff", ".woff2", ".eot", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff",
		".pdf", ".mp3", ".wav", ".ogg", ".flac", ".m4a", ".mp4", ".mov", ".webm", ".avi", ".heic", ".psd", ".sqlite", ".db", ".parquet", ".npy")
	textNames = set(".cursorrules", ".windsurfrules", ".clinerules", "makefile", "dockerfile", ".npmrc", ".pypirc", "pip.conf", ".env")
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Classify decides a file's kind from its name and content.
func Classify(name string, data []byte) ir.FileKind {
	base := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(base))
	// Content beats extension for things that matter.
	switch {
	case IsExecutable(data):
		return ir.FileBinary
	case isPyc(data) || compiledExt[ext]:
		return ir.FileCompiled
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		if documentExt[ext] {
			return ir.FileDocument
		}
		return ir.FileArchive
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		return ir.FileArchive
	}
	switch {
	case documentExt[ext]:
		return ir.FileDocument
	case archiveExt[ext]:
		return ir.FileArchive
	case markdownExt[ext]:
		return ir.FileMarkdown
	case scriptExt[ext]:
		return ir.FileScript
	case configExt[ext], textNames[base]:
		return ir.FileConfig
	}
	if dataExt[ext] {
		return ir.FileData
	}
	if looksLikeText(data) {
		if bytes.HasPrefix(data, []byte("#!")) {
			return ir.FileScript
		}
		return ir.FileText
	}
	return ir.FileBinary
}

// IsExecutable recognizes ELF, Mach-O and PE (Windows) executables.
func IsExecutable(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch {
	case bytes.HasPrefix(b, []byte("\x7fELF")),
		bytes.HasPrefix(b, []byte("MZ")),
		bytes.HasPrefix(b, []byte{0xfe, 0xed, 0xfa, 0xce}), bytes.HasPrefix(b, []byte{0xfe, 0xed, 0xfa, 0xcf}),
		bytes.HasPrefix(b, []byte{0xce, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(b, []byte{0xcf, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(b, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return true
	}
	return false
}

// isPyc recognizes CPython bytecode: a 2-byte version magic followed by "\r\n".
func isPyc(b []byte) bool {
	return len(b) >= 16 && b[2] == '\r' && b[3] == '\n' && b[1] < 0x10 && b[0] != 0
}

func looksLikeText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	sample := b
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	return utf8.Valid(sample) || utf8.Valid(sample[:len(sample)-3])
}

// DetectKind guesses what kind of add-on an artifact is from its files.
func DetectKind(a *ir.Artifact) ir.Kind {
	hasInstr := false
	for _, f := range a.Files {
		base := strings.ToLower(filepath.Base(f.Path))
		switch {
		case base == "skill.md":
			return ir.KindSkill
		case strings.HasSuffix(f.Path, ".claude-plugin/plugin.json"), strings.HasSuffix(f.Path, ".codex-plugin/plugin.json"):
			return ir.KindPlugin
		}
	}
	for _, f := range a.Files {
		base := strings.ToLower(filepath.Base(f.Path))
		if base == "plugin.json" || base == "marketplace.json" {
			return ir.KindPlugin
		}
		if f.Kind == ir.FileConfig && (strings.Contains(f.Text, "\"mcpServers\"") || strings.Contains(f.Text, "[mcp_servers")) {
			return ir.KindMCPConfig
		}
		switch base {
		case "agents.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md":
			hasInstr = true
		}
		if strings.HasSuffix(base, ".instructions.md") || strings.HasSuffix(base, ".prompt.md") || strings.HasSuffix(base, ".agent.md") {
			hasInstr = true
		}
	}
	if hasInstr {
		return ir.KindInstructions
	}
	return ir.KindUnknown
}
