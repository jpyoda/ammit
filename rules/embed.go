// Package rulepack embeds ammit's default rule packs into the binary.
//
// Rules are plain JSON so they can be reviewed in pull requests and loaded
// without extra dependencies. See docs/rules.md for the format.
package rulepack

import "embed"

// FS holds the default rule packs.
//
//go:embed *.json
var FS embed.FS
