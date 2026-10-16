import { FastifyBaseLogger, FastifyInstance } from 'fastify'
import {
  createOwnedPasteRecord,
  recordOwnedShareView,
  markOwnedShareStatus,
} from '../lib/account-shares.js'
import { ensureAccountSystemSchema } from '../lib/account-schema.js'
import { auditActorFor, recordShareEvent, recordShareView } from '../lib/audit.js'
import { config } from '../lib/config.js'
import { getPrisma } from '../lib/db.js'
import { consumePasteView, ensurePasteSchema } from '../lib/pastes-db.js'
import { getPrincipal, requireScope } from '../lib/principal.js'
import {
  generateSlug,
  effectiveMaxViews,
  isExpired,
  isUniqueConstraintError,
  resolveMaxViews,
  resolveShareExpiry,
  viewsRemaining,
} from '../lib/utils.js'
import {
  createPasteSchema,
  getPasteParamsSchema,
  rejectUnsupportedRecipient,
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
    const principal = await getPrincipal(request)

    // An authenticated create is always recorded as owned; a principal that
    // may not create shares is refused rather than silently made anonymous.
    if (principal) {
      requireScope(principal, 'shares:create')
    }

    rejectUnsupportedRecipient(body.recipient)

    if (Buffer.from(body.ciphertext, 'base64').length > config.MAX_PASTE_SIZE_BYTES) {
      return reply.code(413).send({
        error: 'Paste too large',
        maxSize: config.MAX_PASTE_SIZE_BYTES,
      })
    }

    const slug = body.slug || generateSlug()
    const expiresAt = resolveShareExpiry(body)
    const maxViews = resolveMaxViews(body)

    try {
      const paste = await prisma.paste.create({
        data: {
          slug,
          ciphertext: body.ciphertext,
          nonce: body.nonce,
          salt: body.salt,
          kdf_params: body.kdf_params,
          expires_at: expiresAt,
          burn_after_read: maxViews === 1,
          max_views: maxViews,
          recipient_fingerprint: body.recipient?.fingerprint ?? null,
          wrapped_key: body.recipient?.wrapped_key ?? null,
        },
      })

      const response: CreatePasteResponse = {
        slug: paste.slug,
        expires_at: paste.expires_at,
        max_views: paste.max_views,
      }

      if (principal) {
        try {
          const owned = await createOwnedPasteRecord({
            user_id: principal.user.id,
            resource_id: paste.id,
            slug: paste.slug,
            expires_at: paste.expires_at,
            burn_after_read: paste.burn_after_read,
            is_password_protected: Boolean(paste.salt),
            max_views: paste.max_views,
            recipient_fingerprint: paste.recipient_fingerprint,
            recipient_agent_id: paste.recipient_agent_id,
            created_via_token_id: principal.token_id,
          })
          await recordShareEvent(
            owned,
            'share.created',
            auditActorFor(principal, owned.user_id),
            {
              request,
              details: { max_views: paste.max_views, expires_at: paste.expires_at },
            }
          )
        } catch (error: unknown) {
          // An authenticated create must not quietly become an anonymous,
          // unrevocable share: undo it and report the failure.
          fastify.log.error({ err: error, pasteId: paste.id }, 'Failed to record owned paste')
          await prisma.paste.deleteMany({ where: { id: paste.id } })
          return reply.code(500).send({ error: 'Internal server error' })
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
          view_count: true,
          max_views: true,
          recipient_fingerprint: true,
          recipient_user_id: true,
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

      const maxViews = effectiveMaxViews(paste)
      const response: PasteMetaResponse = {
        slug: paste.slug,
        created_at: paste.created_at,
        expires_at: paste.expires_at,
        burn_after_read: paste.burn_after_read,
        is_burned: paste.is_burned,
        password_protected: Boolean(paste.salt),
        salt: paste.salt || undefined,
        kdf_params: paste.kdf_params || undefined,
        max_views: maxViews,
        views_remaining: viewsRemaining(maxViews, paste.view_count),
        recipient: paste.recipient_fingerprint
          ? { fingerprint: paste.recipient_fingerprint }
          : null,
        requires_recipient_auth: Boolean(paste.recipient_user_id),
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
    // Resolved before any view is consumed, so a bad token can't burn a share.
    const principal = await getPrincipal(request)

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

      const maxViews = effectiveMaxViews(paste)
      let isBurned = false
      let viewCount: number

      if (maxViews !== null) {
        // Conditional update so concurrent readers can't exceed the limit; the
        // last view wipes the content in the same statement. Every reader that
        // got a view returns the copy it read above.
        const consumed = await consumePasteView(paste.id, maxViews)

        if (!consumed) {
          return reply.code(410).send({ error: 'Paste has been burned' })
        }

        isBurned = consumed.is_burned
        viewCount = consumed.view_count
      } else {
        const updatedPaste = await prisma.paste.update({
          where: { id: paste.id },
          data: {
            view_count: { increment: 1 },
          },
        })
        viewCount = updatedPaste.view_count
      }

      const owned = await recordOwnedShareView({
        share_type: 'paste',
        resource_id: paste.id,
        next_status: isBurned ? 'burned' : undefined,
      }).catch((error: unknown) => {
        fastify.log.error({ err: error, pasteId: paste.id }, 'Failed to update owned paste metrics')
        return null
      })

      if (owned) {
        const actor = auditActorFor(principal, owned.user_id)
        await recordShareView(owned, actor, { view: viewCount, max_views: maxViews }, request)
        if (isBurned) {
          await recordShareEvent(owned, 'share.burned', actor, { request })
        }
      }

      const response: GetPasteResponse = {
        metadata: {
          id: paste.id,
          slug: paste.slug,
          created_at: paste.created_at,
          expires_at: paste.expires_at,
          burn_after_read: paste.burn_after_read,
          is_burned: isBurned,
          view_count: viewCount,
          max_views: maxViews,
          views_remaining: viewsRemaining(maxViews, viewCount),
          salt: paste.salt || undefined,
          kdf_params: paste.kdf_params || undefined,
        },
        ciphertext: paste.ciphertext,
        nonce: paste.nonce,
        salt: paste.salt || undefined,
        kdf_params: paste.kdf_params || undefined,
        wrapped_key: paste.wrapped_key || undefined,
        recipient_fingerprint: paste.recipient_fingerprint || undefined,
      }

      if (maxViews !== null) {
        reply.header('Cache-Control', 'no-store')
      }

      return response
    } catch (error: unknown) {
      fastify.log.error({ err: error }, 'Failed to retrieve paste')
      return reply.code(500).send({ error: 'Internal server error' })
    }
  })
}
