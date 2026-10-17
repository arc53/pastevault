package secrets

import (
	"context"
	"net/http"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/store"
)

// Resolver turns handles into secret values for run and inject.
type Resolver struct {
	// Server is the configured server (--server): the default for handles
	// without server=, and the store the default agent's secrets live in.
	Server string
	// PublicBase is Server's web origin (share URLs on it map to Server).
	PublicBase string
	// NewClient returns an API client, carrying credentials, for share
	// handles on server.
	NewClient func(server string) (*pv.Client, error)

	shares map[string][]byte
}

// Resolve returns the value a handle names. allowURLs also accepts https
// share URLs (inject templates); .env.pv values only take pv:// handles.
//
// Share handles must point at a paste without a view limit: reading one
// from run or inject must not burn it, so view-limited shares are refused
// with a hint to save them first (pastevault get <ref> --save NAME).
func (r *Resolver) Resolve(ctx context.Context, raw string, allowURLs bool) ([]byte, error) {
	handle, err := pv.ParseHandle(raw, r.Server, r.PublicBase, allowURLs)
	if err != nil {
		return nil, err
	}

	var value []byte
	switch handle.Kind {
	case pv.HandleSecret:
		value, err = r.secret(handle)
	default:
		value, err = r.share(ctx, handle)
	}
	if err != nil {
		return nil, err
	}

	if handle.Var == "" {
		return value, nil
	}
	selected, found, err := pv.LookupDotenv(value, handle.Var)
	if err != nil {
		return nil, pv.UsageError("%s: the content is not a dotenv file (%v)", handle, err)
	}
	if !found {
		return nil, pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "%s: the content has no %s", handle, handle.Var)
	}

	return []byte(selected), nil
}

func (r *Resolver) secret(handle pv.Handle) ([]byte, error) {
	server := r.Server
	if handle.Server != "" {
		server = handle.Server
	}
	identity, err := pv.ResolveLocalAgent(server, handle.Agent)
	if err != nil {
		return nil, err
	}
	target, err := store.Open(server, identity)
	if err != nil {
		return nil, err
	}
	_, payload, err := target.Get(handle.Name)
	if err != nil {
		return nil, err
	}

	return payload.Bytes()
}

func (r *Resolver) share(ctx context.Context, handle pv.Handle) ([]byte, error) {
	ref := handle.Share
	// The same share may be named by several handles (var=...); the key is
	// part of the cache key, so a handle without it never gets the content.
	cacheKey := ref.Server + "\x00" + ref.Slug + "\x00" + string(ref.Key)
	if value, ok := r.shares[cacheKey]; ok {
		return value, nil
	}

	client, err := r.NewClient(ref.Server)
	if err != nil {
		return nil, err
	}
	saveHint := "pastevault get " + handle.String() + " --save NAME, then use pv://secret/NAME"

	if ref.Kind == pv.ShareKindFileShare {
		return nil, pv.UsageError("%s is a file share; file shares can't be used as values directly: %s", handle, saveHint)
	}
	meta, err := client.GetPasteMeta(ctx, ref.Slug)
	if pv.IsStatus(err, http.StatusNotFound) && ref.Kind != pv.ShareKindPaste {
		if _, fileErr := client.GetFileShareMeta(ctx, ref.Slug); fileErr == nil {
			return nil, pv.UsageError("%s is a file share; file shares can't be used as values directly: %s", handle, saveHint)
		}
	}
	if err != nil {
		return nil, err
	}

	// Opening a view-limited share would use up (or burn) a view on every
	// run; it has to be saved once instead.
	if meta.MaxViews != nil || meta.BurnAfterRead {
		return nil, pv.UsageError("%s has a view limit, so run and inject won't open it: %s", handle, saveHint)
	}

	var identity *pv.AgentIdentity
	switch {
	case meta.Recipient != nil:
		if len(ref.Key) > 0 || meta.PasswordProtected || meta.Salt != "" {
			return nil, pv.NewError(pv.ExitDecrypt, pv.CodeSealedConflict, "the server claims %s is sealed, but the link carries a key or the share a password; refusing it", handle)
		}
		if identity, err = pv.FindIdentityByFingerprint(ref.Server, meta.Recipient.Fingerprint); err != nil {
			return nil, err
		}
		if identity == nil {
			return nil, pv.NewError(pv.ExitDecrypt, pv.CodeSealedShare, "%s is sealed to agent key %s, which is not on this machine", handle, meta.Recipient.Fingerprint)
		}
		if meta.RequiresRecipientAuth && !client.HasAuthToken() {
			return nil, pv.NewError(pv.ExitAuth, pv.CodeAuth, "%s can only be opened signed in to the recipient's account (pastevault login, or PASTEVAULT_TOKEN)", handle)
		}
	case meta.PasswordProtected || meta.Salt != "":
		return nil, pv.UsageError("%s is password protected; run and inject can't prompt: %s", handle, saveHint)
	case len(ref.Key) == 0:
		return nil, pv.NewError(pv.ExitUsage, pv.CodeKeyRequired, "%s has no #k= key", handle)
	}

	paste, err := client.GetPaste(ctx, ref.Slug)
	if err != nil {
		return nil, err
	}
	if paste.Metadata.Slug != ref.Slug {
		return nil, pv.DecryptError("the server answered %s with another share", handle)
	}

	key := ref.Key
	if identity != nil {
		if paste.RecipientFingerprint != "" && paste.RecipientFingerprint != identity.Fingerprint {
			return nil, pv.DecryptError("%s is sealed to another key", handle)
		}
		if key, err = pv.UnwrapKey(paste.WrappedKey, identity.Keys().PrivateKey, pv.PasteWrapContext(ref.Slug)); err != nil {
			return nil, pv.DecryptError("could not unwrap the key of %s", handle)
		}
	}
	content, err := pv.DecryptPaste(paste.Ciphertext, paste.Nonce, key, ref.Slug)
	if err != nil {
		return nil, pv.DecryptError("could not decrypt %s: wrong key, or the content was tampered with", handle)
	}

	value := []byte(content.Body)
	if r.shares == nil {
		r.shares = map[string][]byte{}
	}
	r.shares[cacheKey] = value

	return value, nil
}
