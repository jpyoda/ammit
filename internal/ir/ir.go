// Package ir defines the Artifact intermediate representation (IR).
//
// Every agent add-on (skill, plugin, MCP configuration, instruction file),
// wherever it comes from, is converted into an Artifact before analysis.
// Analyzers only ever read the IR, never the original bytes on disk, so
// evasion tricks (archives, encodings, hidden characters) are undone once,
// in the normalizer, for every analyzer at the same time.
package ir

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// SchemaVersion is bumped whenever the JSON shape of the IR changes in a
// way that out-of-process analyzer plugins would notice.
const SchemaVersion = "1"

// Kind is the kind of add-on an Artifact represents.
type Kind string

const (
	KindSkill        Kind = "skill"
	KindPlugin       Kind = "plugin"
	KindMCPConfig    Kind = "mcp-config"
	KindInstructions Kind = "instructions"
	KindUnknown      Kind = "unknown"
)

// FileKind classifies a single file inside an Artifact.
type FileKind string

const (
	FileMarkdown FileKind = "markdown"
	FileScript   FileKind = "script"
	FileConfig   FileKind = "config"
	FileText     FileKind = "text"
	FileCompiled FileKind = "compiled"
	FileBinary   FileKind = "binary"
	FileArchive  FileKind = "archive"
	FileDocument FileKind = "document"
	// FileData is a known media or data format (fonts, images, PDFs,
	// audio): opaque, but not code.
	FileData FileKind = "data"
)

// IsText reports whether files of this kind carry analyzable text.
func (k FileKind) IsText() bool {
	switch k {
	case FileMarkdown, FileScript, FileConfig, FileText:
		return true
	}
	return false
}

// Note is an observation the collector or normalizer made about a file,
// e.g. "whitespace inflation at line 12". The structural analyzer turns
// notes into findings.
type Note struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
}

// File is one file of an Artifact, possibly extracted from an archive or
// derived by the normalizer (decoded base64, text pulled from a document,
// printable strings pulled from a compiled file).
type File struct {
	// Path is the logical path inside the artifact. Files extracted from an
	// archive use "!/" as separator: "bundle.zip!/scripts/run.py".
	Path   string   `json:"path"`
	Kind   FileKind `json:"kind"`
	Size   int64    `json:"size"`
	SHA256 string   `json:"sha256"`
	// Text is the normalized text used for analysis. Invisible Unicode is
	// removed. Empty for binary files.
	Text string `json:"text,omitempty"`
	// Derived is true for files the normalizer produced rather than found.
	Derived bool `json:"derived,omitempty"`
	// Parent is the Path of the file this one was extracted or derived from.
	Parent string `json:"parent,omitempty"`
	Notes  []Note `json:"notes,omitempty"`

	Raw []byte `json:"-"`
}

// AddNote records an observation on the file.
func (f *File) AddNote(code string, line int, msg string) {
	f.Notes = append(f.Notes, Note{Code: code, Message: msg, Line: line})
}

// Origin returns the path of the file on disk this file comes from,
// following Parent links out of archives and derived content. Reports point
// users at files they can open.
func (a *Artifact) Origin(f *File) string {
	cur := f
	for i := 0; i < 16 && cur.Parent != ""; i++ {
		p := a.File(cur.Parent)
		if p == nil {
			return cur.Parent
		}
		cur = p
	}
	return cur.Path
}

// Reference is something an add-on points to outside itself: a URL, a git
// repository, or a package it installs. References are what change after
// review, so they are tracked and re-scanned.
type Reference struct {
	Type  string `json:"type"` // url | git | package
	Value string `json:"value"`
	File  string `json:"file"`
	Line  int    `json:"line,omitempty"`
}

// Artifact is the normalized representation of one add-on.
type Artifact struct {
	SchemaVersion string      `json:"schema_version"`
	Name          string      `json:"name"`
	Root          string      `json:"root"`
	Kind          Kind        `json:"kind"`
	SHA256        string      `json:"sha256"`
	Files         []*File     `json:"files"`
	References    []Reference `json:"references,omitempty"`
	// Notes holds artifact-level observations (limits hit, unreadable paths).
	Notes []Note `json:"notes,omitempty"`

	index map[string]*File
}

// New returns an empty Artifact.
func New(name, root string) *Artifact {
	return &Artifact{SchemaVersion: SchemaVersion, Name: name, Root: root, Kind: KindUnknown, index: map[string]*File{}}
}

// Add appends a file, computing its hash.
func (a *Artifact) Add(f *File) {
	if f.SHA256 == "" {
		sum := sha256.Sum256(f.Raw)
		f.SHA256 = hex.EncodeToString(sum[:])
	}
	if f.Size == 0 {
		f.Size = int64(len(f.Raw))
	}
	if a.index == nil {
		a.index = map[string]*File{}
	}
	a.Files = append(a.Files, f)
	a.index[f.Path] = f
}

// File returns the file with the given logical path, or nil.
func (a *Artifact) File(path string) *File {
	if a.index == nil {
		a.index = map[string]*File{}
		for _, f := range a.Files {
			a.index[f.Path] = f
		}
	}
	return a.index[path]
}

// AddNote records an artifact-level observation.
func (a *Artifact) AddNote(code, msg string) {
	a.Notes = append(a.Notes, Note{Code: code, Message: msg})
}

// ComputeHash sets the artifact hash: a hash over the sorted (path, hash)
// pairs of every non-derived file. Two copies of the same add-on hash the
// same wherever they were found; any change to any file changes the hash.
func (a *Artifact) ComputeHash() {
	type pair struct{ p, h string }
	var ps []pair
	for _, f := range a.Files {
		if !f.Derived {
			ps = append(ps, pair{f.Path, f.SHA256})
		}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].p < ps[j].p })
	h := sha256.New()
	for _, p := range ps {
		h.Write([]byte(p.p))
		h.Write([]byte{0})
		h.Write([]byte(p.h))
		h.Write([]byte{0})
	}
	a.SHA256 = hex.EncodeToString(h.Sum(nil))
}
