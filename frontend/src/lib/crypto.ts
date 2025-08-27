import { xchacha20poly1305 } from '@noble/ciphers/chacha'
import { PasteContent, EncryptionResult, PasswordEncryptionResult } from '@/types'

const ALGORITHM_VERSION = 'v1'
const AAD_PREFIX = 'pastevault'

function createAssociatedData(pasteId: string, version: string = ALGORITHM_VERSION): Uint8Array {
  const data = `${AAD_PREFIX}:${pasteId}:${version}`
  return new TextEncoder().encode(data)
}

function base64urlEncode(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode.apply(null, Array.from(bytes)))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '=='.slice(0, (4 - base64.length % 4) % 4)
  const binary = atob(padded)
  return new Uint8Array(Array.from(binary).map(c => c.charCodeAt(0)))
}

export async function generateRandomKey(): Promise<Uint8Array> {
  return crypto.getRandomValues(new Uint8Array(32))
}

export async function generateNonce(): Promise<Uint8Array> {
  return crypto.getRandomValues(new Uint8Array(24))
}

export async function deriveKeyFromPassword(
  password: string,
  salt?: Uint8Array
): Promise<{ key: Uint8Array; salt: Uint8Array; params: string }> {
  const saltBytes = salt || crypto.getRandomValues(new Uint8Array(16))
  const params = {
    iterations: 600000,
    algorithm: 'PBKDF2',
    hash: 'SHA-256',
    keyLen: 32,
  }
  
  // Use WebCrypto PBKDF2 for password derivation (simpler than Argon2)
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes.buffer as ArrayBuffer,
      iterations: params.iterations,
      hash: params.hash,
    },
    keyMaterial,
    params.keyLen * 8
  )
  
  return {
    key: new Uint8Array(derivedBits),
    salt: saltBytes,
    params: JSON.stringify(params)
  }
}

export async function encryptPaste(
  content: PasteContent,
  pasteId: string = crypto.randomUUID()
): Promise<EncryptionResult> {
  const key = await generateRandomKey()
  const nonce = await generateNonce()
  const plaintext = new TextEncoder().encode(JSON.stringify(content))
  const aad = createAssociatedData(pasteId)
  
  const cipher = xchacha20poly1305(key, nonce, aad)
  const ciphertext = cipher.encrypt(plaintext)
  
  return {
    ciphertext: base64urlEncode(ciphertext),
    nonce: base64urlEncode(nonce),
    key
  }
}

export async function encryptPasteWithPassword(
  content: PasteContent,
  password: string,
  pasteId: string = crypto.randomUUID()
): Promise<PasswordEncryptionResult> {
  const { key, salt, params } = await deriveKeyFromPassword(password)
  const nonce = await generateNonce()
  const plaintext = new TextEncoder().encode(JSON.stringify(content))
  const aad = createAssociatedData(pasteId)
  
  const cipher = xchacha20poly1305(key, nonce, aad)
  const ciphertext = cipher.encrypt(plaintext)
  
  return {
    ciphertext: base64urlEncode(ciphertext),
    nonce: base64urlEncode(nonce),
    salt: base64urlEncode(salt),
    kdf_params: params
  }
}

export async function decryptPaste(
  ciphertext: string,
  nonce: string,
  key: Uint8Array,
  pasteId: string
): Promise<PasteContent> {
  const ciphertextBytes = base64urlDecode(ciphertext)
  const nonceBytes = base64urlDecode(nonce)
  const aad = createAssociatedData(pasteId)
  
  const cipher = xchacha20poly1305(key, nonceBytes, aad)
  const plaintext = cipher.decrypt(ciphertextBytes)
  
  const content = new TextDecoder().decode(plaintext)
  return JSON.parse(content)
}

export async function decryptPasteWithPassword(
  ciphertext: string,
  nonce: string,
  salt: string,
  kdfParams: string,
  password: string,
  pasteId: string
): Promise<PasteContent> {
  const saltBytes = base64urlDecode(salt)
  const { key } = await deriveKeyFromPassword(password, saltBytes)
  
  return decryptPaste(ciphertext, nonce, key, pasteId)
}

export function extractKeyFromFragment(): string | null {
  if (typeof window === 'undefined') return null
  const fragment = window.location.hash
  const match = fragment.match(/[#&]k=([A-Za-z0-9_-]+)/)
  return match ? match[1] : null
}

export function createShareUrl(slug: string, key?: Uint8Array): string {
  const baseUrl = `${window.location.origin}/p/${slug}`
  if (key) {
    const keyStr = base64urlEncode(key)
    return `${baseUrl}#k=${keyStr}`
  }
  return baseUrl
}

export async function calculateContentHash(content: PasteContent): Promise<string> {
  const plaintext = JSON.stringify(content)
  const encoder = new TextEncoder()
  const data = encoder.encode(plaintext)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = new Uint8Array(hashBuffer)
  return base64urlEncode(hashArray)
}
