'use client'

import { useEffect, useState } from 'react'
import { remark } from 'remark'
import remarkGfm from 'remark-gfm'
import remarkRehype from 'remark-rehype'
import rehypeSanitize, { defaultSchema } from 'rehype-sanitize'
import rehypeStringify from 'rehype-stringify'
import rehypeHighlight from 'rehype-highlight'

interface MarkdownRendererProps {
  content: string
  className?: string
}

export function MarkdownRenderer({ content, className }: MarkdownRendererProps) {
  const [html, setHtml] = useState('')

  useEffect(() => {

    const processMarkdown = async () => {
      try {
        // Allow highlight.js classes through the sanitizer
        const schema = structuredClone(defaultSchema)
        ;(schema as any).attributes = (schema as any).attributes || {}
        ;(schema as any).tagNames = [ ...((schema as any).tagNames || []), 'span' ]
        ;(schema as any).attributes.code = [
          ...(((schema as any).attributes.code) || []),
          ['className', 'hljs', /^language-/]
        ]
        ;(schema as any).attributes.span = [
          ...(((schema as any).attributes.span) || []),
          ['className', /^hljs-/]
        ]

        // Process markdown with remark/rehype
        const processed = await remark()
          .use(remarkGfm)
          .use(remarkRehype, {
            allowDangerousHtml: false,
            clobberPrefix: 'user-content-',
          })
          .use(rehypeSanitize, schema)
          .use(rehypeHighlight, { detect: true, ignoreMissing: true })
          .use(rehypeStringify)
          .process(content)

        const html = String(processed)
        setHtml(html)
      } catch (error) {
        console.error('Failed to process markdown:', error)
        setHtml(`<p>Error processing content</p>`)
      }
    }

    processMarkdown()
  }, [content])

  if (!html) {
    return (
      <div className={`animate-pulse ${className}`}>
        <div className="h-4 bg-muted rounded mb-2"></div>
        <div className="h-4 bg-muted rounded mb-2 w-3/4"></div>
        <div className="h-4 bg-muted rounded mb-4 w-1/2"></div>
        <div className="h-20 bg-muted rounded"></div>
      </div>
    )
  }

  return (
    <div 
      className={`prose prose-slate dark:prose-invert max-w-none ${className}`}
      dangerouslySetInnerHTML={{ __html: html }}
      style={{
        // Custom CSS for Shiki themes
        colorScheme: 'light dark',
      }}
    />
  )
}
