// Return paths after sign-in ("/account?redirectTo=…"). Only same-origin
// paths are allowed: a value must start with a single "/", contain no
// backslashes, whitespace or control characters (also once percent-decoded,
// since browsers and routers normalise "%5C" and "%09"), and still resolve
// to this origin. Returns pathname + search + hash, or null.
const UNSAFE_CHARACTERS = /[\\\s\u0000-\u001f\u007f-\u009f\u2028\u2029]/

export function safeRedirectTarget(value: string | null | undefined, origin?: string): string | null {
  const base = origin ?? (typeof window === 'undefined' ? null : window.location.origin)
  if (!value || !base || !value.startsWith('/') || value.startsWith('//')) {
    return null
  }

  let decoded: string
  try {
    decoded = decodeURIComponent(value)
  } catch {
    return null
  }
  if (UNSAFE_CHARACTERS.test(value) || UNSAFE_CHARACTERS.test(decoded) || decoded.startsWith('//')) {
    return null
  }

  let url: URL
  try {
    url = new URL(value, base)
  } catch {
    return null
  }
  if (url.origin !== new URL(base).origin) {
    return null
  }

  const target = `${url.pathname}${url.search}${url.hash}`
  return target.startsWith('/') && !target.startsWith('//') ? target : null
}

// "/account?redirectTo=<path>", for a path on this site.
export function signInHref(returnTo: string): string {
  return `/account?redirectTo=${encodeURIComponent(returnTo)}`
}
