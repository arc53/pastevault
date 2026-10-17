package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

// maxTemplateBytes caps an inject template.
const maxTemplateBytes = 10 * 1024 * 1024

// placeholderPattern matches {{ pv://... }} and {{ https://host/p/... }}.
var placeholderPattern = regexp.MustCompile(`\{\{\s*((?:pv|https?)://[^\s{}]+)\s*\}\}`)

// runInject is "pastevault inject -i TEMPLATE [-o OUT | --stdout]": every
// {{ handle }} placeholder is replaced by the secret it names. The output
// file is written 0600. Unresolvable handles exit 125, like run.
func runInject(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("inject", "pastevault inject -i TEMPLATE [-o OUT [--overwrite] | --stdout] [flags]")
	input := fs.String("i", "", "Template file (- for stdin)")
	fs.StringVar(input, "in", "", "Same as -i")
	output := fs.String("o", "", "Write the result to this file (mode 0600)")
	fs.StringVar(output, "out", "", "Same as -o")
	toStdout := fs.Bool("stdout", false, "Write the result to stdout")
	overwrite := fs.Bool("overwrite", false, "Replace an existing output file")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("inject takes no arguments; use -i TEMPLATE")
	}
	if *input == "" {
		return pv.UsageError("-i TEMPLATE is required")
	}
	if (*output == "") == !*toStdout {
		return pv.UsageError("choose exactly one of -o OUT and --stdout")
	}
	if *toStdout && out.json() {
		return pv.UsageError("--stdout can't be combined with --json; use -o OUT")
	}
	if *output != "" {
		// Before anything is resolved (a share handle opens a share).
		if err := pv.CheckWritableTarget(*output, *overwrite); err != nil {
			return err
		}
	}

	var template []byte
	if *input == "-" {
		template, err = readValue(a.stdin, maxTemplateBytes, "the template on stdin")
	} else {
		template, err = readValueFile(*input, maxTemplateBytes)
	}
	if err != nil {
		return err
	}

	resolver := runResolver(common)
	resolved := map[string][]byte{}
	var resolveErr error
	result := placeholderPattern.ReplaceAllFunc(template, func(match []byte) []byte {
		if resolveErr != nil {
			return match
		}
		handle := string(placeholderPattern.FindSubmatch(match)[1])
		value, ok := resolved[handle]
		if !ok {
			value, resolveErr = resolver.Resolve(ctx, handle, true)
			if resolveErr != nil {
				resolveErr = fmt.Errorf("%s: %w", redactHandle(handle), resolveErr)
				return match
			}
			resolved[handle] = value
		}
		return value
	})
	if resolveErr != nil {
		return &commandExit{code: exitRunUnresolved, err: resolveErr}
	}

	if *toStdout {
		_, err := io.Copy(a.stdout, bytes.NewReader(result))
		return err
	}
	if err := pv.WritePrivateFile(*output, result, *overwrite); err != nil {
		return err
	}
	if out.json() {
		return out.emitJSON(map[string]any{"written_to": *output, "placeholders": len(resolved)})
	}
	out.infof("Wrote %s (%d secret(s) filled in, mode 0600).", *output, len(resolved))

	return nil
}

// redactHandle drops a #k= key from a handle for messages.
func redactHandle(handle string) string {
	if before, _, found := bytes.Cut([]byte(handle), []byte("#")); found {
		return string(before) + "#…"
	}

	return handle
}
