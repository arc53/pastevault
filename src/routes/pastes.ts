import { FastifyInstance } from 'fastify'
import { prisma } from '../lib/db'
import { config } from '../lib/config'
import { generateSlug, calculateExpiryDate, isExpired } from '../lib/utils'
import { createPasteSchema, getPasteParamsSchema } from '../lib/validation'
import { CreatePasteRequest, CreatePasteResponse, GetPasteResponse } from '../types'

export async function pastesRoute(fastify: FastifyInstance) {
  fastify.post<{
    Body: CreatePasteRequest
  }>('/pastes', async (request, reply) => {
    const body = createPasteSchema.parse(request.body)

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

      return reply.code(201).send(response)
    } catch (error: unknown) {
      fastify.log.error({ err: error }, 'Failed to create paste')
      return reply.code(500).send({ error: 'Internal server error' })
    }
  })

  fastify.get<{
    Params: { slug: string }
  }>('/pastes/:slug', async (request, reply) => {
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
        await prisma.paste.delete({ where: { id: paste.id } })
        return reply.code(410).send({ error: 'Paste has expired' })
      }

      let shouldBurn = false
      if (paste.burn_after_read && paste.view_count === 0) {
        shouldBurn = true
      }

      const updatedPaste = await prisma.paste.update({
        where: { id: paste.id },
        data: {
          view_count: { increment: 1 },
          ...(shouldBurn && { is_burned: true }),
        },
      })

      const response: GetPasteResponse = {
        metadata: {
          id: paste.id,
          slug: paste.slug,
          created_at: paste.created_at,
          expires_at: paste.expires_at,
          burn_after_read: paste.burn_after_read,
          is_burned: updatedPaste.is_burned,
          view_count: updatedPaste.view_count,
          salt: paste.salt || undefined,
          kdf_params: paste.kdf_params || undefined,
        },
        ciphertext: paste.ciphertext,
        nonce: paste.nonce,
        salt: paste.salt || undefined,
        kdf_params: paste.kdf_params || undefined,
      }

      return response
    } catch (error: unknown) {
      fastify.log.error({ err: error }, 'Failed to retrieve paste')
      return reply.code(500).send({ error: 'Internal server error' })
    }
  })

}