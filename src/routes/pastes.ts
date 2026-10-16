import { FastifyBaseLogger, FastifyInstance } from 'fastify'
import {
  createOwnedPasteRecord,
  recordOwnedShareView,
  markOwnedShareStatus,
} from '../lib/account-shares.js'
import { getOptionalAuthSession } from '../lib/auth-session.js'
import { ensureAccountSystemSchema } from '../lib/account-schema.js'
import { config } from '../lib/config.js'
import { getPrisma } from '../lib/db.js'
import { ensurePasteSchema } from '../lib/pastes-db.js'
import {
  generateSlug,
  calculateExpiryDate,
  isExpired,
  isUniqueConstraintError,
} from '../lib/utils.js'
import {
  createPasteSchema,
  getPasteParamsSchema,
  validationErrorHandler,
} from '../lib/validation.js'
import {
  CreatePasteRequest,
  CreatePasteResponse,
  GetPasteResponse,
  PasteMetaResponse,
} from '../types/index.js'

async function expirePaste(log: FastifyBaseLogger, pasteId: string) {
  await markOwnedShareStatus('paste', pasteId, 'expired').catch((error: unknown) => {
    log.error({ err: error, pasteId }, 'Failed to mark paste as expired')
  })
  await getPrisma().paste.deleteMany({ where: { id: pasteId } })
}

export async function pastesRoute(fastify: FastifyInstance) {
  await ensurePasteSchema()
  if (!config.DISABLE_AUTH) {
    await ensureAccountSystemSchema()
  }

  fastify.setErrorHandler(validationErrorHandler)

  fastify.post<{
    Body: CreatePasteRequest
  }>('/pastes', async (request, reply) => {
    const prisma = getPrisma()
    const body = createPasteSchema.parse(request.body)
    const session = await getOptionalAuthSession(request)

    if (Buffer.from(body.ciphertext, 'base64').length > config.MAX_PASTE_SIZE_BYTES) {
      return reply.code(413).send({
        error: 'Paste too large',
        maxSize: config.MAX_PASTE_SIZE_BYTES,
      })
    }

    const slug = body.slug || generateSlug()
    const expiresAt = body.expires_in_hours 
      ? calculateExpiryDate(body.expires_in_hours) 
      : null

    try {
      const paste = await prisma.paste.create({
        data: {
          slug,
          ciphertext: body.ciphertext,
          nonce: body.nonce,
          salt: body.salt,
          kdf_params: body.kdf_params,
          expires_at: expiresAt,
          burn_after_read: body.burn_after_read,
        },
      })

      const response: CreatePasteResponse = {
        slug: paste.slug,
        expires_at: paste.expires_at,
      }

      if (session) {
        try {
          await createOwnedPasteRecord({
            user_id: session.user.id,
            resource_id: paste.id,
            slug: paste.slug,
            expires_at: paste.expires_at,
            burn_after_read: paste.burn_after_read,
            is_password_protected: Boolean(paste.salt),
          })
        } catch (error: unknown) {
          fastify.log.error({ err: error, pasteId: paste.id }, 'Failed to record owned paste')
        }
      }

      return reply.code(201).send(response)
    } catch (error: unknown) {
      if (isUniqueConstraintError(error)) {
        return reply.code(409).send({ error: 'A paste with this slug already exists' })
      }

      fastify.log.error({ err: error }, 'Failed to create paste')
      return reply.code(500).send({ error: 'Internal server error' })
    }
  })

  fastify.get<{
    Params: { slug: string }
  }>('/pastes/:slug/meta', async (request, reply) => {
    const prisma = getPrisma()
    const { slug } = getPasteParamsSchema.parse(request.params)

    try {
      const paste = await prisma.paste.findUnique({
        where: { slug },
        select: {
          id: true,
          slug: true,
          created_at: true,
          expires_at: true,
          burn_after_read: true,
          is_burned: true,
          salt: true,
          kdf_params: true,
        },
      })

      if (!paste) {
        return reply.code(404).send({ error: 'Paste not found' })
      }

      if (paste.is_burned) {
        return reply.code(410).send({ error: 'Paste has been burned' })
      }

      if (paste.expires_at && isExpired(paste.expires_at)) {
        await expirePaste(fastify.log, paste.id)
        return reply.code(410).send({ error: 'Paste has expired' })
      }

      const response: PasteMetaResponse = {
        slug: paste.slug,
        created_at: paste.created_at,
        expires_at: paste.expires_at,
        burn_after_read: paste.burn_after_read,
        is_burned: paste.is_burned,
        password_protected: Boolean(paste.salt),
        salt: paste.salt || undefined,
        kdf_params: paste.kdf_params || undefined,
      }

      return reply.header('Cache-Control', 'no-store').send(response)
    } catch (error: unknown) {
      fastify.log.error({ err: error }, 'Failed to retrieve paste metadata')
      return reply.code(500).send({ error: 'Internal server error' })
    }
  })

  // HEAD would run the GET handler and burn the paste for a link scanner.
  fastify.head('/pastes/:slug', async (_request, reply) => {
    return reply
      .code(405)
      .header('Allow', 'GET')
      .send({ error: 'Method not allowed: use GET to read this paste' })
  })

  fastify.get<{
    Params: { slug: string }
  }>('/pastes/:slug', { exposeHeadRoute: false }, async (request, reply) => {
    const prisma = getPrisma()
    const { slug } = getPasteParamsSchema.parse(request.params)

    try {
      const paste = await prisma.paste.findUnique({
        where: { slug },
      })

      if (!paste) {
        return reply.code(404).send({ error: 'Paste not found' })
      }

      if (paste.is_burned) {
        return reply.code(410).send({ error: 'Paste has been burned' })
      }

      if (paste.expires_at && isExpired(paste.expires_at)) {
        await expirePaste(fastify.log, paste.id)
        return reply.code(410).send({ error: 'Paste has expired' })
      }

      let isBurned = false
      let viewCount: number

      if (paste.burn_after_read) {
        // Conditional update so exactly one concurrent reader wins the burn. The
        // ciphertext is wiped in the same statement; only the winner returns the
        // copy it read above.
        const burned = await prisma.paste.updateMany({
          where: { id: paste.id, is_burned: false },
          data: {
            is_burned: true,
            view_count: { increment: 1 },
            ciphertext: '',
            nonce: '',
            salt: null,
            kdf_params: null,
          },
        })

        if (burned.count === 0) {
          return reply.code(410).send({ error: 'Paste has been burned' })
        }

        isBurned = true
        viewCount = paste.view_count + 1
      } else {
        const updatedPaste = await prisma.paste.update({
          where: { id: paste.id },
          data: {
            view_count: { increment: 1 },
          },
        })
        viewCount = updatedPaste.view_count
      }

      await recordOwnedShareView({
        share_type: 'paste',
        resource_id: paste.id,
        next_status: isBurned ? 'burned' : undefined,
      }).catch((error: unknown) => {
        fastify.log.error({ err: error, pasteId: paste.id }, 'Failed to update owned paste metrics')
      })

      const response: GetPasteResponse = {
        metadata: {
          id: paste.id,
          slug: paste.slug,
          created_at: paste.created_at,
          expires_at: paste.expires_at,
          burn_after_read: paste.burn_after_read,
          is_burned: isBurned,
          view_count: viewCount,
          salt: paste.salt || undefined,
          kdf_params: paste.kdf_params || undefined,
        },
        ciphertext: paste.ciphertext,
        nonce: paste.nonce,
        salt: paste.salt || undefined,
        kdf_params: paste.kdf_params || undefined,
      }

      if (isBurned) {
        reply.header('Cache-Control', 'no-store')
      }

      return response
    } catch (error: unknown) {
      fastify.log.error({ err: error }, 'Failed to retrieve paste')
      return reply.code(500).send({ error: 'Internal server error' })
    }
  })
}
