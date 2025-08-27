'use client'

import { Editor as MonacoEditor } from '@monaco-editor/react'
import { useTheme } from 'next-themes'
import { useEffect, useState } from 'react'

interface EditorProps {
  value: string
  onChange: (value: string) => void
  language?: string
  placeholder?: string
  className?: string
  height?: string | number
}

export function Editor({
  value,
  onChange,
  language = 'markdown',
  placeholder = 'Start typing...',
  className,
  height = '400px'
}: EditorProps) {
  const { theme, resolvedTheme } = useTheme()
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return (
      <div 
        className={`border rounded-md bg-background dark:bg-[#1A1F26] flex items-center justify-center ${className}`}
        style={{ height: typeof height === 'string' ? height : `${height}px` }}
      >
        <span className="text-muted-foreground">Loading editor...</span>
      </div>
    )
  }

  return (
    <div className={`border rounded-md overflow-hidden bg-white dark:bg-[#1A1F26] dark:border-[#2F353D] ${className}`}>
      <MonacoEditor
        key={resolvedTheme}
        height={height}
        language={language}
        theme={resolvedTheme === 'dark' ? 'pastevault-dark' : 'pastevault-light'}
        value={value}
        onChange={(value) => onChange(value || '')}
        options={{
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          fontSize: 14,
          lineHeight: 1.5,
          padding: { top: 16, bottom: 16 },
          automaticLayout: true,
          wordWrap: 'on',
          wrappingStrategy: 'advanced',
          suggest: {
            showKeywords: false,
            showSnippets: false,
          },
          quickSuggestions: false,
          parameterHints: { enabled: false },
          occurrencesHighlight: 'off',
          selectionHighlight: false,
          renderLineHighlight: 'none',
          hideCursorInOverviewRuler: true,
          overviewRulerBorder: false,
          scrollbar: {
            vertical: 'auto',
            horizontal: 'auto',
            verticalScrollbarSize: 12,
            horizontalScrollbarSize: 12,
          },
          bracketPairColorization: { enabled: true },
          guides: {
            bracketPairs: false,
            bracketPairsHorizontal: false,
            highlightActiveIndentation: false,
            indentation: false,
          },
        }}
        beforeMount={(monaco) => {
          // Add custom theme support
          monaco.editor.defineTheme('pastevault-light', {
            base: 'vs',
            inherit: true,
            rules: [
              { token: 'comment', foreground: '6B7280', fontStyle: 'italic' },
              { token: 'keyword', foreground: '16A34A', fontStyle: 'bold' },
              { token: 'string', foreground: '22C55E' },
            ],
            colors: {
              'editor.background': '#FFFFFF',
              'editor.foreground': '#262C33',
              'editor.lineHighlightBackground': '#F8F9FA',
              'editorCursor.foreground': '#16A34A',
              'editor.selectionBackground': '#E0F2E0',
              'editorWidget.background': '#FFFFFF',
              'editorWidget.border': '#E5E7EB',
            },
          })
          
          monaco.editor.defineTheme('pastevault-dark', {
            base: 'vs-dark',
            inherit: true,
            rules: [
              { token: 'comment', foreground: '8B9BB5', fontStyle: 'italic' },
              { token: 'keyword', foreground: '22C55E', fontStyle: 'bold' },
              { token: 'string', foreground: '86EFAC' },
            ],
            colors: {
              'editor.background': '#1A1F26',
              'editor.foreground': '#EAEBEC',
              'editor.lineHighlightBackground': '#242A32',
              'editorCursor.foreground': '#22C55E',
              'editor.selectionBackground': '#1F2F1F',
              'editorWidget.background': '#1A1F26',
              'editorWidget.border': '#2F353D',
            },
          })
        }}
        onMount={(editor, monaco) => {
          // Set placeholder
          if (!value && placeholder) {
            editor.setModel(
              editor.getModel() || 
              monaco.editor.createModel('', language)
            )
            editor.getModel()?.setValue('')
          }
        }}
      />
    </div>
  )
}
