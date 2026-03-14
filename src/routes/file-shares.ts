import { FastifyInstance } from 'fastify'
import {
  createOwnedFileShareRecord,
  markOwnedShareStatus,
  recordOwnedShareView,
} from '../lib/account-shares.js'
import { ensureAccountSystemSchema } from '../lib/account-schema.js'
import { getOptionalAuthSession } from '../lib/auth-session.js'
import { config } from '../lib/config.js'
import {
  completeFileShareRecord,
  createFileShareRecord,
  deleteFileSharesByIds,
  ensureFileShareSchema,
  getFileShareRecordBySlug,
  incrementFileShareViewCount,
} from '../lib/file-shares-db.js'
import {
  deleteFileShareObjects,
  downloadFileShareChunk,
  isFileSharingConfigured,
  uploadFileShareChunk,
} from '../lib/file-storage.js'
import { calculateExpiryDate, generateSlug, isExpired } from '../lib/utils.js'
import {
  completeFileShareSchema,
  createFileShareSchema,
  fileShareChunkParamsSchema,
  getFileShareParamsSchema,
} from '../lib/validation.js'
import {
  CapabilitiesResponse,
  CompleteFileShareRequest,
  CreateFileShareRequest,
  CreateFileShareResponse,
  GetFileShareResponse,
} from '../types/index.js'

const XCHACHA20POLY1305_TAG_BYTES = 16

async function purgeFileShare(slug: string, id: string) {
  await deleteFileShareObjects(slug)
  await deleteFileSharesByIds([id])
}

export async function fileSharesRoute(fastify: FastifyInstance) {
  await ensureFileShareSchema()
  await ensureAccountSystemSchema()
  const maxEncryptedChunkSizeBytes =
    config.FILE_CHUNK_SIZE_BYTES + XCHACHA20POLY1305_TAG_BYTES

  fastify.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer' },
    async (_request: unknown, body: Buffer) => body
  )

  fastify.get('/capabilities', async (_request, reply) => {
    const response: CapabilitiesResponse = {
      file_shares: {
        enabled: isFileSharingConfigured(),
        max_share_size_bytes: config.MAX_FILE_SHARE_SIZE_BYTES,
        max_files: config.MAX_FILE_SHARE_FILES,
        chunk_size_bytes: config.FILE_CHUNK_SIZE_BYTES,
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

    try {
      const shareId = await createFileShareRecord({
        slug,
        expires_at: expiresAt,
        salt: body.salt,
        kdf_params: body.kdf_params,
        file_count: body.file_count,
        total_size_bytes: body.total_size_bytes,
      })

      const response: CreateFileShareResponse = {
        slug,
        expires_at: expiresAt,
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
            is_password_protected: Boolean(body.salt),
          })
        } catch (error: unknown) {
          fastify.log.error({ err: error, shareId }, 'Failed to record owned file share')
        }
      }

      return reply.code(201).send(response)
    } catch (error: unknown) {
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

      if (share.expires_at && isExpired(share.expires_at)) {
        await markOwnedShareStatus('file_share', share.id, 'expired').catch(
          (error: unknown) => {
            fastify.log.error({ err: error, shareId: share.id }, 'Failed to mark file share as expired')
          }
        )
        await purgeFileShare(share.slug, share.id)
        return reply.code(410).send({ error: 'File share has expired' })
      }

      if (share.is_complete) {
        return reply.code(409).send({ error: 'File share is already complete' })
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

    if (share.expires_at && isExpired(share.expires_at)) {
      await markOwnedShareStatus('file_share', share.id, 'expired').catch((error: unknown) => {
        fastify.log.error({ err: error, shareId: share.id }, 'Failed to mark file share as expired')
      })
      await purgeFileShare(share.slug, share.id)
      return reply.code(410).send({ error: 'File share has expired' })
    }

    if (share.is_complete) {
      return reply.code(409).send({ error: 'File share is already complete' })
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

  fastify.get<{
    Params: { slug: string }
  }>('/file-shares/:slug', async (request, reply) => {
    const { slug } = getFileShareParamsSchema.parse(request.params)
    const share = await getFileShareRecordBySlug(slug)

    if (!share || !share.is_complete) {
      return reply.code(404).send({ error: 'File share not found' })
    }

    if (share.expires_at && isExpired(share.expires_at)) {
      await markOwnedShareStatus('file_share', share.id, 'expired').catch((error: unknown) => {
        fastify.log.error({ err: error, shareId: share.id }, 'Failed to mark file share as expired')
      })
      await purgeFileShare(share.slug, share.id)
      return reply.code(410).send({ error: 'File share has expired' })
    }

    try {
      await incrementFileShareViewCount(share.id)
      await recordOwnedShareView({
        share_type: 'file_share',
        resource_id: share.id,
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
        },
        manifest_ciphertext: share.manifest_ciphertext!,
        manifest_nonce: share.manifest_nonce!,
        salt: share.salt || undefined,
        kdf_params: share.kdf_params || undefined,
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
      await markOwnedShareStatus('file_share', share.id, 'expired').catch((error: unknown) => {
        fastify.log.error({ err: error, shareId: share.id }, 'Failed to mark file share as expired')
      })
      await purgeFileShare(share.slug, share.id)
      return reply.code(410).send({ error: 'File share has expired' })
    }

    try {
      const chunk = await downloadFileShareChunk(slug, fileId, chunkIndex)
      return reply
        .type('application/octet-stream')
        .header('Cache-Control', 'private, max-age=300')
        .send(chunk)
    } catch (error: unknown) {
      fastify.log.error({ err: error }, 'Failed to download file share chunk')
      return reply.code(404).send({ error: 'File chunk not found' })
    }
  })
}
