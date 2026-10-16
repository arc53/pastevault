package pastevault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Pinned agent keys (spec §4), so a server can't silently swap the key a
// share is sealed to:
//
//	<ConfigDir>/known_agents.json
//	{"servers": {"<server>": {"<name>": {fingerprint, public_key, first_seen, source}}}}
//
// "agent init" pins the new agent as "self". "put --to NAME" pins an unknown
// agent on first use ("tofu") and refuses (exit 8) when the server's key no
// longer matches the pin. "agent trust NAME FP" re-pins after the user has
// verified FP out of band ("manual").
const (
	PinSourceSelf   = "self"
	PinSourceTOFU   = "tofu"
	PinSourceManual = "manual"
)

type KnownAgent struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	FirstSeen   string `json:"first_seen"`
	Source      string `json:"source"`
}

type knownAgentsFile struct {
	Servers map[string]map[string]KnownAgent `json:"servers"`
}

func knownAgentsPath() (string, error) {
	configDir, err := ConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "known_agents.json"), nil
}

func readKnownAgents() (knownAgentsFile, string, error) {
	path, err := knownAgentsPath()
	if err != nil {
		return knownAgentsFile{}, "", err
	}

	known := knownAgentsFile{}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return knownAgentsFile{}, "", err
	default:
		if err := json.Unmarshal(data, &known); err != nil {
			return knownAgentsFile{}, "", fmt.Errorf("could not parse %s: %w", path, err)
		}
	}
	if known.Servers == nil {
		known.Servers = map[string]map[string]KnownAgent{}
	}

	return known, path, nil
}

// LoadPins returns the pinned agents of server by name.
func LoadPins(server string) (map[string]KnownAgent, error) {
	key, err := normalizeServerKey(server)
	if err != nil {
		return nil, err
	}
	known, _, err := readKnownAgents()
	if err != nil {
		return nil, err
	}

	pins := known.Servers[key]
	if pins == nil {
		pins = map[string]KnownAgent{}
	}

	return pins, nil
}

// PinAgent records publicKey as agent name's key on server.
func PinAgent(server, name string, publicKey []byte, source string) (KnownAgent, error) {
	key, err := normalizeServerKey(server)
	if err != nil {
		return KnownAgent{}, err
	}
	known, path, err := readKnownAgents()
	if err != nil {
		return KnownAgent{}, err
	}

	pin := KnownAgent{
		Fingerprint: Fingerprint(publicKey),
		PublicKey:   EncodeBase64URL(publicKey),
		FirstSeen:   time.Now().UTC().Format(time.RFC3339),
		Source:      source,
	}
	if known.Servers[key] == nil {
		known.Servers[key] = map[string]KnownAgent{}
	}
	if previous, ok := known.Servers[key][name]; ok && previous.Fingerprint == pin.Fingerprint {
		pin.FirstSeen = previous.FirstSeen
	}
	known.Servers[key][name] = pin

	if err := writePrivateJSON(path, known); err != nil {
		return KnownAgent{}, WrapError(ExitLocalFile, CodeLocalFile, err, "could not save the pinned agent key")
	}

	return pin, nil
}

// PinMismatchError explains a key that differs from the pinned one (exit 8)
// and how to recover after verifying the new fingerprint out of band.
func PinMismatchError(name, pinned, current string) *CLIError {
	return NewError(ExitFingerprint, CodeFingerprint,
		"the server's key for agent %s has fingerprint %s, but %s is pinned on this machine. The key may have been replaced on the server. "+
			"Nothing was shared. If the agent was re-created, compare the fingerprint with `pastevault agent show %s` on the agent's machine, then run: pastevault agent trust %s %s",
		name, current, pinned, name, name, current)
}

// VerifyAgentKey checks a public key the server lists for agent name
// against what this machine already knows: its own key file for that name,
// then the pin. An agent seen for the first time is pinned (trust on first
// use) and newlyPinned is true. A different key is a PinMismatchError.
func VerifyAgentKey(server, name string, publicKey []byte) (newlyPinned bool, err error) {
	fingerprint := Fingerprint(publicKey)

	local, err := LoadAgentIdentity(server, name)
	if err != nil {
		return false, err
	}
	if local != nil && local.Fingerprint != fingerprint {
		return false, PinMismatchError(name, local.Fingerprint, fingerprint)
	}

	pins, err := LoadPins(server)
	if err != nil {
		return false, err
	}
	if pin, ok := pins[name]; ok {
		if pin.Fingerprint != fingerprint {
			return false, PinMismatchError(name, pin.Fingerprint, fingerprint)
		}
		return false, nil
	}

	if _, err := PinAgent(server, name, publicKey, PinSourceTOFU); err != nil {
		return false, err
	}

	return true, nil
}
