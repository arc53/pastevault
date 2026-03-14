import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import {
  base64urlDecode,
  base64urlEncode,
  deriveKeyFromPassword,
  generateNonce,
  generateRandomKey,
} from '@/lib/crypto'
import { FileShareManifest } from '@/types'

const FILE_SHARE_VERSION = 'v1'
const FILE_SHARE_AAD_PREFIX = 'pastevault:file-share'

function createManifestAssociatedData(slug: string) {
  return new TextEncoder().encode(
    `${FILE_SHARE_AAD_PREFIX}:manifest:${slug}:${FILE_SHARE_VERSION}`
  )
}

function createChunkAssociatedData(slug: string, fileId: string, chunkIndex: number) {
  return new TextEncoder().encode(
    `${FILE_SHARE_AAD_PREFIX}:chunk:${slug}:${fileId}:${chunkIndex}:${FILE_SHARE_VERSION}`
  )
}

export async function prepareFileShareEncryption(password?: string) {
  if (password) {
    const { key, salt, params } = await deriveKeyFromPassword(password)
    return {
      key,
      salt: base64urlEncode(salt),
      kdf_params: params,
    }
  }

  return {
    key: await generateRandomKey(),
  }
}

export async function encryptFileChunk(
  bytes: Uint8Array,
  key: Uint8Array,
  slug: string,
  fileId: string,
  chunkIndex: number
) {
  const nonce = await generateNonce()
  const aad = createChunkAssociatedData(slug, fileId, chunkIndex)
  const cipher = xchacha20poly1305(key, nonce, aad)

  return {
    ciphertext: cipher.encrypt(bytes),
    nonce: base64urlEncode(nonce),
  }
}

export function decryptFileChunk(
  ciphertext: Uint8Array,
  nonce: string,
  key: Uint8Array,
  slug: string,
  fileId: string,
  chunkIndex: number
) {
  const nonceBytes = base64urlDecode(nonce)
  const aad = createChunkAssociatedData(slug, fileId, chunkIndex)
  const cipher = xchacha20poly1305(key, nonceBytes, aad)

  return cipher.decrypt(ciphertext)
}

export async function encryptFileShareManifest(
  manifest: FileShareManifest,
  key: Uint8Array,
  slug: string
) {
  const nonce = await generateNonce()
  const plaintext = new TextEncoder().encode(JSON.stringify(manifest))
  const aad = createManifestAssociatedData(slug)
  const cipher = xchacha20poly1305(key, nonce, aad)

  return {
    manifest_ciphertext: base64urlEncode(cipher.encrypt(plaintext)),
    manifest_nonce: base64urlEncode(nonce),
  }
}

export function decryptFileShareManifest(
  ciphertext: string,
  nonce: string,
  key: Uint8Array,
  slug: string
) {
  const nonceBytes = base64urlDecode(nonce)
  const ciphertextBytes = base64urlDecode(ciphertext)
  const aad = createManifestAssociatedData(slug)
  const cipher = xchacha20poly1305(key, nonceBytes, aad)
  const plaintext = cipher.decrypt(ciphertextBytes)

  return JSON.parse(new TextDecoder().decode(plaintext)) as FileShareManifest
}

export function formatBytes(bytes: number) {
  if (bytes === 0) {
    return '0 B'
  }

  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const exponent = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  )
  const value = bytes / 1024 ** exponent

  return `${value >= 10 || exponent === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[exponent]}`
}
