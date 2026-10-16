import { FastifyInstance, FastifyReply } from 'fastify'
import {
  createOwnedFileShareRecord,
  markOwnedShareStatus,
  recordOwnedShareView,
} from '../lib/account-shares.js'
import { ensureAccountSystemSchema } from '../lib/account-schema.js'
import { getOptionalAuthSession } from '../lib/auth-session.js'
import { config } from '../lib/config.js'
import {
  burnFileShareRecord,
  completeFileShareRecord,
  createFileShareRecord,
  deleteFileSharesByIds,
  ensureFileShareSchema,
  extendFileShareDownloadGrant,
  FileShareRecord,
  getFileShareRecordBySlug,
  incrementFileShareViewCount,
} from '../lib/file-shares-db.js'
import {
  deleteFileShareObjects,
  downloadFileShareChunk,
  isFileSharingConfigured,
  uploadFileShareChunk,
} from '../lib/file-storage.js'
import {
  calculateExpiryDate,
  generateSecretToken,
  generateSlug,
  hashSecretToken,
  isExpired,
  isUniqueConstraintError,
  readHeader,
  secretTokenMatches,
} from '../lib/utils.js'
import {
  completeFileShareSchema,
  createFileShareSchema,
  fileShareChunkParamsSchema,
  getFileShareParamsSchema,
  validationErrorHandler,
} from '../lib/validation.js'
import {
  CapabilitiesResponse,
  CompleteFileShareRequest,
  CreateFileShareRequest,
  CreateFileShareResponse,
  FileShareMetaResponse,
  GetFileShareResponse,
} from '../types/index.js'

const XCHACHA20POLY1305_TAG_BYTES = 16
const UPLOAD_TOKEN_HEADER = 'x-upload-token'
const DOWNLOAD_GRANT_HEADER = 'x-download-grant'
// A burned share's chunks stay downloadable while the reader keeps fetching
// them: every valid chunk request slides the grant forward by the idle window
// (FILE_SHARE_DOWNLOAD_GRANT_SECONDS, 15 min by default). A fixed window would
// destroy large or slow downloads midway (2 GB at 10 Mbit/s takes ~27 min), so
// the total lifetime is capped by a deadline scaled to the share size instead.
const DOWNLOAD_GRANT_MIN_LIFETIME_MS = 60 * 60 * 1000
const DOWNLOAD_GRANT_MAX_LIFETIME_MS = 24 * 60 * 60 * 1000
const DOWNLOAD_GRANT_SLOWEST_BYTES_PER_SECOND = 1024 * 1024

function downloadGrantIdleMs() {
  return config.FILE_SHARE_DOWNLOAD_GRANT_SECONDS * 1000
}

function nextDownloadGrantExpiry(share: FileShareRecord, burnedAt: Date) {
  const sizeBytes = Number(share.total_size_bytes) || 0
  const lifetimeMs = Math.min(
    DOWNLOAD_GRANT_MAX_LIFETIME_MS,
    Math.max(
      DOWNLOAD_GRANT_MIN_LIFETIME_MS,
      (sizeBytes / DOWNLOAD_GRANT_SLOWEST_BYTES_PER_SECOND) * 1000
    )
  )

  return new Date(
    Math.min(Date.now() + downloadGrantIdleMs(), burnedAt.getTime() + lifetimeMs)
  )
}

function rejectHead(_request: unknown, reply: FastifyReply) {
  return reply
    .code(405)
    .header('Allow', 'GET')
    .send({ error: 'Method not allowed: use GET to open this share' })
}

async function purgeFileShare(slug: string, id: string) {
  await deleteFileShareObjects(slug)
  await deleteFileSharesByIds([id])
}

function checkUploadToken(share: FileShareRecord, token: string | undefined) {
  if (!token) {
    return {
      status: 401,
      error:
        'Missing upload token (X-Upload-Token). Your PasteVault client is out of date; please update it and try again.',
    }
  }

  if (!secretTokenMatches(token, share.upload_token_hash)) {
    return { status: 403, error: 'Invalid upload token' }
  }

  return null
}

export async function fileSharesRoute(fastify: FastifyInstance) {
  await ensureFileShareSchema()
  if (!config.DISABLE_AUTH) {
    await ensureAccountSystemSchema()
  }

  fastify.setErrorHandler(validationErrorHandler)
  const maxEncryptedChunkSizeBytes =
    config.FILE_CHUNK_SIZE_BYTES + XCHACHA20POLY1305_TAG_BYTES

  fastify.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer' },
    async (_request: unknown, body: Buffer) => body
  )

  fastify.get('/capabilities', async (_request, reply) => {
    const response: CapabilitiesResponse = {
      auth: {
        enabled: !config.DISABLE_AUTH,
        signup_enabled: !config.DISABLE_AUTH && !config.DISABLE_SIGNUP,
      },
      file_shares: {
        enabled: isFileSharingConfigured(),
        max_share_size_bytes: config.MAX_FILE_SHARE_SIZE_BYTES,
        max_files: config.MAX_FILE_SHARE_FILES,
        chunk_size_bytes: config.FILE_CHUNK_SIZE_BYTES,
        burn_after_read: true,
      },
    }

    return reply.send(response)
  })

  fastify.post<{
    Body: CreateFileShareRequest
  }>('/file-shares', async (request, reply) => {
    if (!isFileSharingConfigured()) {
      return reply.code(503).send({
        error: 'File sharing is not configured on this server',
      })
    }

    const body = createFileShareSchema.parse(request.body)
    const session = await getOptionalAuthSession(request)
    const slug = body.slug || generateSlug()
    const expiresAt = body.expires_in_hours
      ? calculateExpiryDate(body.expires_in_hours)
      : null
    const uploadToken = generateSecretToken()

    try {
      const shareId = await createFileShareRecord({
        slug,
        expires_at: expiresAt,
        salt: body.salt,
        kdf_params: body.kdf_params,
        file_count: body.file_count,
        total_size_bytes: body.total_size_bytes,
        burn_after_read: body.burn_after_read,
        upload_token_hash: hashSecretToken(uploadToken),
      })

      const response: CreateFileShareResponse = {
        slug,
        expires_at: expiresAt,
        burn_after_read: body.burn_after_read,
        upload_token: uploadToken,
      }

      if (session) {
        try {
          await createOwnedFileShareRecord({
            user_id: session.user.id,
            resource_id: shareId,
            slug,
            expires_at: expiresAt,
            file_count: body.file_count,
            total_size_bytes: body.total_size_bytes,
            burn_after_read: body.burn_after_read,
            is_password_protected: Boolean(body.salt),
          })
        } catch (error: unknown) {
          fastify.log.error({ err: error, shareId }, 'Failed to record owned file share')
        }
      }

      return reply.code(201).send(response)
    } catch (error: unknown) {
      if (isUniqueConstraintError(error)) {
        return reply.code(409).send({ error: 'A file share with this slug already exists' })
      }

      fastify.log.error({ err: error }, 'Failed to create file share')
      return reply.code(500).send({ error: 'Internal server error' })
    }
  })

  fastify.put<{
    Params: { slug: string; fileId: string; chunkIndex: string }
    Body: Buffer
  }>(
    '/file-shares/:slug/chunks/:fileId/:chunkIndex',
    {
      bodyLimit: maxEncryptedChunkSizeBytes,
    },
    async (request, reply) => {
      if (!isFileSharingConfigured()) {
        return reply.code(503).send({
          error: 'File sharing is not configured on this server',
        })
      }

      const { slug, fileId, chunkIndex } = fileShareChunkParamsSchema.parse(
        request.params
      )
      const share = await getFileShareRecordBySlug(slug)

      if (!share) {
        return reply.code(404).send({ error: 'File share not found' })
      }

      if (share.is_complete) {
        return reply.code(409).send({ error: 'File share is already complete' })
      }

      const tokenError = checkUploadToken(
        share,
        readHeader(request.headers, UPLOAD_TOKEN_HEADER)
      )
      if (tokenError) {
        return reply.code(tokenError.status).send({ error: tokenError.error })
      }

      if (share.expires_at && isExpired(share.expires_at)) {
        await markOwnedShareStatus('file_share', share.id, 'expired').catch(
          (error: unknown) => {
            fastify.log.error({ err: error, shareId: share.id }, 'Failed to mark file share as expired')
          }
        )
        await purgeFileShare(share.slug, share.id)
        return reply.code(410).send({ error: 'File share has expired' })
      }

      const body = request.body
      if (!Buffer.isBuffer(body) || body.length === 0) {
        return reply.code(400).send({ error: 'Chunk body is required' })
      }

      if (body.length > maxEncryptedChunkSizeBytes) {
        return reply.code(413).send({
          error: 'Chunk too large',
          maxSize: maxEncryptedChunkSizeBytes,
        })
      }

      try {
        await uploadFileShareChunk(slug, fileId, chunkIndex, body)
        return reply.code(204).send()
      } catch (error: unknown) {
        fastify.log.error({ err: error }, 'Failed to upload file share chunk')
        return reply.code(500).send({ error: 'Internal server error' })
      }
    }
  )

  fastify.post<{
    Params: { slug: string }
    Body: CompleteFileShareRequest
  }>('/file-shares/:slug/complete', async (request, reply) => {
    const { slug } = getFileShareParamsSchema.parse(request.params)
    const body = completeFileShareSchema.parse(request.body)
    const share = await getFileShareRecordBySlug(slug)

    if (!share) {
      return reply.code(404).send({ error: 'File share not found' })
    }

    if (share.is_complete) {
      return reply.code(409).send({ error: 'File share is already complete' })
    }

    const tokenError = checkUploadToken(
      share,
      readHeader(request.headers, UPLOAD_TOKEN_HEADER)
    )
    if (tokenError) {
      return reply.code(tokenError.status).send({ error: tokenError.error })
    }

    if (share.expires_at && isExpired(share.expires_at)) {
      await markOwnedShareStatus('file_share', share.id, 'expired').catch((error: unknown) => {
        fastify.log.error({ err: error, shareId: share.id }, 'Failed to mark file share as expired')
      })
      await purgeFileShare(share.slug, share.id)
      return reply.code(410).send({ error: 'File share has expired' })
    }

    try {
      const updated = await completeFileShareRecord(
        slug,
        body.manifest_ciphertext,
        body.manifest_nonce
      )

      if (!updated) {
        return reply.code(409).send({ error: 'File share could not be completed' })
      }

      await markOwnedShareStatus('file_share', share.id, 'active').catch((error: unknown) => {
        fastify.log.error({ err: error, shareId: share.id }, 'Failed to activate owned file share')
      })

      return reply.send({ slug })
    } catch (error: unknown) {
      fastify.log.error({ err: error }, 'Failed to complete file share')
      return reply.code(500).send({ error: 'Internal server error' })
    }
  })

  const expireShare = async (share: FileShareRecord) => {
    await markOwnedShareStatus('file_share', share.id, 'expired').catch((error: unknown) => {
      fastify.log.error({ err: error, shareId: share.id }, 'Failed to mark file share as expired')
    })
    await purgeFileShare(share.slug, share.id)
  }

  // Deletes a burned share's chunks promptly once its grant lapses. The stored
  // expiry is re-read first because chunk downloads slide it forward. Timers
  // don't survive a restart; the lazy check on chunk requests and the cleanup
  // job cover that case.
  const schedulePurgeCheck = (id: string, slug: string, delayMs: number) => {
    const timer = setTimeout(() => {
      void (async () => {
        const share = await getFileShareRecordBySlug(slug)
        if (!share || share.id !== id || !share.is_burned) {
          return
        }

        const expiresAt = share.download_grant_expires_at
        if (expiresAt && !isExpired(expiresAt)) {
          schedulePurgeCheck(id, slug, expiresAt.getTime() - Date.now() + 1000)
          return
        }

        await purgeFileShare(share.slug, share.id)
      })().catch((error: unknown) => {
        fastify.log.error({ err: error, shareId: id }, 'Failed to purge burned file share')
      })
    }, delayMs)
    timer.unref()
  }

  fastify.get<{
    Params: { slug: string }
  }>('/file-shares/:slug/meta', async (request, reply) => {
    const { slug } = getFileShareParamsSchema.parse(request.params)
    const share = await getFileShareRecordBySlug(slug)

    if (!share || !share.is_complete) {
      return reply.code(404).send({ error: 'File share not found' })
    }

    if (share.is_burned) {
      return reply.code(410).send({ error: 'File share has been burned' })
    }

    if (share.expires_at && isExpired(share.expires_at)) {
      await expireShare(share)
      return reply.code(410).send({ error: 'File share has expired' })
    }

    const response: FileShareMetaResponse = {
      slug: share.slug,
      created_at: share.created_at,
      expires_at: share.expires_at,
      burn_after_read: share.burn_after_read,
      is_burned: share.is_burned,
      password_protected: Boolean(share.salt),
      salt: share.salt || undefined,
      kdf_params: share.kdf_params || undefined,
      file_count: share.file_count,
      total_size_bytes: share.total_size_bytes,
    }

    return reply.header('Cache-Control', 'no-store').send(response)
  })

  // HEAD would run the GET handler and burn the share for a link scanner.
  fastify.head('/file-shares/:slug', rejectHead)

  fastify.get<{
    Params: { slug: string }
  }>('/file-shares/:slug', { exposeHeadRoute: false }, async (request, reply) => {
    const { slug } = getFileShareParamsSchema.parse(request.params)
    const share = await getFileShareRecordBySlug(slug)

    if (!share || !share.is_complete) {
      return reply.code(404).send({ error: 'File share not found' })
    }

    if (share.is_burned) {
      return reply.code(410).send({ error: 'File share has been burned' })
    }

    if (share.expires_at && isExpired(share.expires_at)) {
      await expireShare(share)
      return reply.code(410).send({ error: 'File share has expired' })
    }

    try {
      let downloadGrant: string | undefined
      let downloadGrantExpiresAt: Date | undefined

      if (share.burn_after_read) {
        const burnedAt = new Date()
        downloadGrant = generateSecretToken()
        downloadGrantExpiresAt = nextDownloadGrantExpiry(share, burnedAt)

        const burned = await burnFileShareRecord(
          share.id,
          hashSecretToken(downloadGrant),
          downloadGrantExpiresAt,
          burnedAt
        )

        if (!burned) {
          return reply.code(410).send({ error: 'File share has been burned' })
        }

        schedulePurgeCheck(
          share.id,
          share.slug,
          downloadGrantExpiresAt.getTime() - Date.now() + 1000
        )
      } else {
        await incrementFileShareViewCount(share.id)
      }

      await recordOwnedShareView({
        share_type: 'file_share',
        resource_id: share.id,
        next_status: share.burn_after_read ? 'burned' : undefined,
      }).catch((error: unknown) => {
        fastify.log.error({ err: error, shareId: share.id }, 'Failed to update owned file share metrics')
      })

      const response: GetFileShareResponse = {
        metadata: {
          id: share.id,
          slug: share.slug,
          created_at: share.created_at,
          expires_at: share.expires_at,
          view_count: share.view_count + 1,
          file_count: share.file_count,
          total_size_bytes: share.total_size_bytes,
          burn_after_read: share.burn_after_read,
          is_burned: share.burn_after_read,
        },
        manifest_ciphertext: share.manifest_ciphertext!,
        manifest_nonce: share.manifest_nonce!,
        salt: share.salt || undefined,
        kdf_params: share.kdf_params || undefined,
        download_grant: downloadGrant,
        download_grant_expires_at: downloadGrantExpiresAt,
      }

      if (share.burn_after_read) {
        reply.header('Cache-Control', 'no-store')
      }

      return reply.send(response)
    } catch (error: unknown) {
      fastify.log.error({ err: error }, 'Failed to load file share')
      return reply.code(500).send({ error: 'Internal server error' })
    }
  })

  fastify.get<{
    Params: { slug: string; fileId: string; chunkIndex: string }
  }>('/file-shares/:slug/chunks/:fileId/:chunkIndex', async (request, reply) => {
    if (!isFileSharingConfigured()) {
      return reply.code(503).send({
        error: 'File sharing is not configured on this server',
      })
    }

    const { slug, fileId, chunkIndex } = fileShareChunkParamsSchema.parse(
      request.params
    )
    const share = await getFileShareRecordBySlug(slug)

    if (!share || !share.is_complete) {
      return reply.code(404).send({ error: 'File share not found' })
    }

    if (share.expires_at && isExpired(share.expires_at)) {
      await expireShare(share)
      return reply.code(410).send({ error: 'File share has expired' })
    }

    if (share.burn_after_read) {
      // Chunks of a burn-after-read share are only served to the reader that
      // opened (and thereby burned) it, and only while its grant is valid.
      if (!share.is_burned) {
        return reply.code(403).send({ error: 'Open the file share before downloading its files' })
      }

      if (
        !share.download_grant_expires_at ||
        isExpired(share.download_grant_expires_at)
      ) {
        await purgeFileShare(share.slug, share.id)
        return reply.code(410).send({ error: 'File share has been burned' })
      }

      if (
        !secretTokenMatches(
          readHeader(request.headers, DOWNLOAD_GRANT_HEADER),
          share.download_grant_hash
        )
      ) {
        return reply.code(403).send({ error: 'Missing or invalid download grant' })
      }

      // Slide the grant while the reader is actively downloading. Skip tiny
      // extensions so a burst of chunk requests doesn't write on every one.
      const nextExpiry = nextDownloadGrantExpiry(share, share.burned_at ?? new Date())
      if (
        nextExpiry.getTime() - share.download_grant_expires_at.getTime() >=
        Math.min(60_000, downloadGrantIdleMs() / 10)
      ) {
        await extendFileShareDownloadGrant(share.id, nextExpiry)
      }
    }

    try {
      const chunk = await downloadFileShareChunk(slug, fileId, chunkIndex)
      return reply
        .type('application/octet-stream')
        .header(
          'Cache-Control',
          share.burn_after_read ? 'no-store' : 'private, max-age=300'
        )
        .send(chunk)
    } catch (error: unknown) {
      fastify.log.error({ err: error }, 'Failed to download file share chunk')
      return reply.code(404).send({ error: 'File chunk not found' })
    }
  })
}
