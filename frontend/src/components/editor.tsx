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
          fontSize: typeof window !== 'undefined' && window.innerWidth <= 768 ? 16 : 14,
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
          contextmenu: false,
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
          // Mobile-specific options for better clipboard support
          accessibilitySupport: 'auto',
          domReadOnly: false,
          readOnly: false,
          // Enable proper mobile input handling
          mouseWheelZoom: false,
          // Ensure textarea is accessible for mobile clipboard
          ariaLabel: placeholder || 'Text editor',
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
          
          // Mobile-specific setup for better clipboard support
          if (typeof window !== 'undefined' && window.innerWidth <= 768) {
            // Ensure the editor's textarea is properly configured for mobile
            const textareaElement = editor.getDomNode()?.querySelector('textarea')
            if (textareaElement) {
              textareaElement.setAttribute('autocomplete', 'off')
              textareaElement.setAttribute('autocorrect', 'off')
              textareaElement.setAttribute('autocapitalize', 'off')
              textareaElement.setAttribute('spellcheck', 'false')
              // Ensure it can handle paste events
              textareaElement.style.userSelect = 'text'
              textareaElement.style.webkitUserSelect = 'text'
            }
          }
        }}
      />
    </div>
  )
}
