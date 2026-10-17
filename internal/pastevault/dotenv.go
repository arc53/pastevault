package pastevault

import (
	"fmt"
	"regexp"
	"strings"
)

// DotenvEntry is one KEY=value assignment.
type DotenvEntry struct {
	Key   string
	Value string
	Line  int
}

var dotenvKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

func validDotenvKey(key string) bool {
	return len(key) <= 256 && dotenvKeyPattern.MatchString(key)
}

// ParseDotenv parses .env / .env.pv content:
//
//	# comment
//	KEY=value                 unquoted: trimmed, " #" starts a comment
//	export KEY=value          "export " is ignored
//	KEY="a \"quoted\"\nvalue" double quotes: \n \r \t \\ \" \$ escapes, may span lines
//	KEY='literal $value'      single quotes: literal, may span lines
//
// There is no variable interpolation: "$OTHER" stays as written. Errors name
// the line, never the value.
func ParseDotenv(data []byte) ([]DotenvEntry, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimPrefix(text, "\uFEFF")
	lines := strings.Split(text, "\n")

	var entries []DotenvEntry
	for index := 0; index < len(lines); index++ {
		lineNumber := index + 1
		line := strings.TrimSpace(lines[index])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, found := strings.CutPrefix(line, "export"); found && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimSpace(rest)
		}

		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found {
			return nil, UsageError("line %d: expected KEY=value", lineNumber)
		}
		if !validDotenvKey(key) {
			return nil, UsageError("line %d: invalid variable name %q", lineNumber, key)
		}
		value = strings.TrimLeft(value, " \t")

		switch {
		case strings.HasPrefix(value, `"`) || strings.HasPrefix(value, `'`):
			quote := value[0]
			parsed, consumed, err := parseQuotedValue(value[1:], lines[index+1:], quote)
			if err != nil {
				return nil, UsageError("line %d: %v", lineNumber, err)
			}
			index += consumed
			value = parsed
		default:
			if comment := strings.Index(value, " #"); comment >= 0 {
				value = value[:comment]
			} else if comment := strings.Index(value, "\t#"); comment >= 0 {
				value = value[:comment]
			}
			value = strings.TrimRight(value, " \t")
		}

		entries = append(entries, DotenvEntry{Key: key, Value: value, Line: lineNumber})
	}

	return entries, nil
}

// parseQuotedValue reads a quoted value starting after the opening quote.
// It returns the value and how many further lines it used.
func parseQuotedValue(first string, more []string, quote byte) (string, int, error) {
	var builder strings.Builder
	current := first
	consumed := 0

	for {
		for position := 0; position < len(current); position++ {
			char := current[position]
			switch {
			case char == quote:
				rest := strings.TrimSpace(current[position+1:])
				if rest != "" && !strings.HasPrefix(rest, "#") {
					return "", 0, fmt.Errorf("unexpected text after the closing quote")
				}
				return builder.String(), consumed, nil
			case char == '\\' && quote == '"' && position+1 < len(current):
				position++
				switch current[position] {
				case 'n':
					builder.WriteByte('\n')
				case 'r':
					builder.WriteByte('\r')
				case 't':
					builder.WriteByte('\t')
				case '\\', '"', '$':
					builder.WriteByte(current[position])
				default:
					builder.WriteByte('\\')
					builder.WriteByte(current[position])
				}
			default:
				builder.WriteByte(char)
			}
		}

		if consumed >= len(more) {
			return "", 0, fmt.Errorf("unterminated %c quote", quote)
		}
		builder.WriteByte('\n')
		current = more[consumed]
		consumed++
	}
}

// LookupDotenv returns the last value of key in dotenv content.
func LookupDotenv(data []byte, key string) (string, bool, error) {
	entries, err := ParseDotenv(data)
	if err != nil {
		return "", false, err
	}

	value, found := "", false
	for _, entry := range entries {
		if entry.Key == key {
			value, found = entry.Value, true
		}
	}

	return value, found, nil
}
