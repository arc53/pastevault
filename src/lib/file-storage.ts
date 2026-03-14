import { mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'
import {
  DeleteObjectsCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3'
import { config } from './config'

let s3Client: S3Client | undefined

function isS3FileSharingConfigured() {
  return Boolean(
    config.S3_BUCKET &&
      config.S3_ACCESS_KEY_ID &&
      config.S3_SECRET_ACCESS_KEY
  )
}

function resolveDataDir() {
  return path.resolve(process.env.DATA_DIR || config.DATA_DIR)
}

function resolveLocalObjectPath(slug: string, fileId: string, chunkIndex: number) {
  return path.join(resolveDataDir(), buildFileShareObjectKey(slug, fileId, chunkIndex))
}

function resolveLocalSharePath(slug: string) {
  return path.join(resolveDataDir(), 'file-shares', slug)
}

function getBucketName() {
  if (!config.S3_BUCKET) {
    throw new Error('File sharing is not configured')
  }

  return config.S3_BUCKET
}

function getS3Client() {
  if (!isS3FileSharingConfigured()) {
    throw new Error('File sharing is not configured')
  }

  if (!s3Client) {
    s3Client = new S3Client({
      region: config.S3_REGION,
      endpoint: config.S3_ENDPOINT,
      forcePathStyle: config.S3_FORCE_PATH_STYLE,
      credentials: {
        accessKeyId: config.S3_ACCESS_KEY_ID!,
        secretAccessKey: config.S3_SECRET_ACCESS_KEY!,
      },
    })
  }

  return s3Client
}

export function isFileSharingConfigured() {
  return isS3FileSharingConfigured() || Boolean(resolveDataDir())
}

export function buildFileShareObjectKey(slug: string, fileId: string, chunkIndex: number) {
  const normalizedChunkIndex = chunkIndex.toString().padStart(8, '0')
  return `file-shares/${slug}/${fileId}/${normalizedChunkIndex}`
}

export async function uploadFileShareChunk(
  slug: string,
  fileId: string,
  chunkIndex: number,
  body: Buffer
) {
  if (!isS3FileSharingConfigured()) {
    const targetPath = resolveLocalObjectPath(slug, fileId, chunkIndex)
    await mkdir(path.dirname(targetPath), { recursive: true })
    await writeFile(targetPath, body)
    return
  }

  const client = getS3Client()
  const bucket = getBucketName()

  await client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: buildFileShareObjectKey(slug, fileId, chunkIndex),
      Body: body,
      ContentType: 'application/octet-stream',
      ContentLength: body.length,
    })
  )
}

export async function downloadFileShareChunk(
  slug: string,
  fileId: string,
  chunkIndex: number
) {
  if (!isS3FileSharingConfigured()) {
    return readFile(resolveLocalObjectPath(slug, fileId, chunkIndex))
  }

  const client = getS3Client()
  const bucket = getBucketName()

  const response = await client.send(
    new GetObjectCommand({
      Bucket: bucket,
      Key: buildFileShareObjectKey(slug, fileId, chunkIndex),
    })
  )

  if (!response.Body) {
    throw new Error('Chunk not found')
  }

  const chunk = await response.Body.transformToByteArray()
  return Buffer.from(chunk)
}

export async function deleteFileShareObjects(slug: string) {
  if (!isS3FileSharingConfigured()) {
    await rm(resolveLocalSharePath(slug), { recursive: true, force: true })
    return
  }

  const client = getS3Client()
  const bucket = getBucketName()
  let continuationToken: string | undefined
  const prefix = `file-shares/${slug}/`

  do {
    const result = await client.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: continuationToken,
      })
    )

    const objects =
      result.Contents?.map((object) => object.Key).filter(
        (key): key is string => Boolean(key)
      ) ?? []

    if (objects.length > 0) {
      await client.send(
        new DeleteObjectsCommand({
          Bucket: bucket,
          Delete: {
            Objects: objects.map((key) => ({ Key: key })),
            Quiet: true,
          },
        })
      )
    }

    continuationToken = result.NextContinuationToken
  } while (continuationToken)
}
