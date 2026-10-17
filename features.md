# PasteVault Features

PasteVault is a secure end-to-end encrypted paste and file sharing application, with a native CLI and an MCP server that let coding agents share files and receive secrets without them passing through a chat.

## 🔐 Security & Encryption

### End-to-End Encryption
- **XChaCha20-Poly1305** authenticated encryption algorithm
- **Zero-knowledge architecture** - server never sees plaintext content
- **Client-side encryption/decryption** in the browser
- **Authenticated encryption** with additional data (AAD) for integrity

### Key Management
- **Random key generation** using `crypto.getRandomValues()`
- **URL fragment storage** - encryption keys stored in URL hash (#k=...) never sent to server
- **Password-based encryption** with PBKDF2 key derivation (600,000 iterations)
- **Secure salt generation** for password-protected pastes

### Agent Keys and Sealed Shares
- **Agent identities** - X25519 key pairs created by `pastevault agent init`; only the public key is registered with the account
- **Sealed shares** - pastes and file shares sealed to an agent (PVWRAP1 key wrap): the link carries no key, and only that agent can open it
- **Recipient auth** - shares sealed to an account agent can only be opened (or burned) by that account
- **Fingerprints and pinning** - `pvk1_…` fingerprints computed client-side, trust on first use, exit 8 / a blocking web error when a key changes
- **Web "Share to agent"** - seal a paste or files to an agent from the browser

### Content Protection
- **Associated data verification** includes paste ID and algorithm version
- **Content integrity validation** with SHA-256 hash calculation
- **Base64url encoding** for safe URL transmission

## 📝 Content Management

### Paste Creation
- **Rich text editor** with Monaco Editor (VS Code-like experience)
- **Syntax highlighting** for multiple programming languages
- **Markdown support** with live preview rendering
- **Mobile-optimized editor** with fallback textarea for mobile devices
- **Multiple content formats**: plain text, markdown, code
- **Draft auto-save** with 7-day retention in localStorage

### Content Features
- **Title and body** text fields
- **Format selection**: markdown, javascript, python, json, xml, yaml, html, css, etc.
- **Content size limits** (configurable, default 1MB)
- **Real-time character/line counting**

## ⏱️ Expiration & Access Control

### Time-based Expiration
- **Flexible expiration times**: 1 hour, 1 day, 1 week, 1 month, never
- **Automatic cleanup** with configurable cron jobs
- **Expired paste deletion** with 410 Gone status
- **Server-side expiration validation**

### Access Control
- **Burn after read** - paste self-destructs after first view
- **View limits** - destroy a paste or file share after N views (1-1000)
- **Minute-level expiry** via the API and CLI (`--expires 15m`)
- **View count tracking** for each paste
- **Password protection** with PBKDF2 key derivation
- **Unique slug generation** with collision prevention

## 🌐 User Interface & Experience

### Modern Web Interface
- **Responsive design** optimized for desktop and mobile
- **Dark/light theme toggle** with system preference detection
- **Internationalization (i18n)** support with next-intl
- **Radix UI components** with Tailwind CSS styling
- **Keyboard accessibility** and screen reader support

### Mobile Experience
- **Mobile-optimized editor** with syntax highlighting
- **Touch-friendly interface** with appropriate button sizing
- **Mobile navigation menu** for smaller screens
- **QR code generation** for easy mobile sharing

### Visual Features
- **Syntax highlighting** powered by Highlight.js
- **Monaco Editor integration** for desktop code editing
- **Markdown rendering** with comprehensive formatting support
- **Loading states and progress indicators**
- **Error handling** with user-friendly messages

## 🔗 Sharing & Distribution

### URL Generation
- **Shareable URLs** with embedded encryption keys
- **QR code generation** for mobile sharing
- **Copy-to-clipboard functionality** with visual feedback
- **Deep linking support** for direct paste access

### API Integration
- **REST API** for programmatic access
- **JSON response format** with comprehensive metadata
- **CORS support** for cross-origin requests
- **Rate limiting** protection against abuse

## 🛠️ Technical Features

### Backend (Fastify)
- **High-performance REST API** with Fastify framework
- **Database support**: SQLite (default) and PostgreSQL
- **Prisma ORM** for type-safe database operations
- **Request validation** with Zod schemas
- **Structured logging** with configurable levels
- **Health check endpoints** for monitoring

### Frontend (Next.js 16)
- **App Router architecture** with server and client components
- **React Query integration** for efficient data fetching
- **TypeScript** for compile-time type safety
- **Server-side rendering** for improved performance
- **Static asset optimization** and code splitting

### Database Schema
- **Paste model** with comprehensive metadata
- **Indexed queries** for optimized performance
- **Migration system** with Prisma
- **Data integrity constraints** and validation

## 🤖 Agents & Automation

### Accounts, Tokens and Audit
- **API tokens** (`pv_pat_…`) - scoped, expiring, revocable, hashed at rest, optionally bound to one agent
- **Owned shares** - list, status, read receipts (`status --wait viewed`) and revoke from the CLI or `/account`
- **Audit log** - metadata-only events for shares, secret requests, agents and tokens (90-day retention, no IPs by default)

### Secret Requests
- **No secrets in chat** - an agent asks for a secret with `pastevault request NAME --why …` (or the MCP `request_secret` tool)
- **Answered in the browser** - the human opens `/r/<code>#fp=…` signed in to the same account; the page verifies the request key and seals the answer to it
- **One-time delivery** - the server only holds the encrypted answer until the agent acknowledges it (at most two minutes after delivery)

### Local Secret Store and `run`
- **`pv://secret/NAME` handles** - answers are stored sealed to the agent key in the local store
- **`pastevault run --env-file .env.pv -- cmd`** - resolves handles into the command's environment and masks the values (and their base64, hex and URL encodings) in its output
- **`pastevault inject`** - fills `{{ pv://… }}` placeholders in config templates

### Native CLI
- **`put` / `get`** for text, `.env` files and files, with `--json` output and stable exit codes for scripts and agents
- **Signed self-update** and install scripts for macOS, Linux and Windows

### MCP Server and Agent Integrations
- **`pastevault mcp`** - stdio MCP server with `send_text`, `send_file`, `receive`, `request_secret`, `request_status`, `list_secrets`, `share_status`, `audit` and `revoke_share`; no tool ever returns a secret's value
- **Confined file access** - roots, credential directory deny list, no symlink escapes, `0600` files, no overwrite without a flag
- **URL elicitation** - clients that support it show the secret request page to the user directly
- **Packaging** - Claude Code plugin and marketplace, Codex and Gemini CLI packaging, an Agent Skill, and an `AGENTS.md` snippet (see `docs/agents.md`)

## 🚀 Deployment & CLI

### CLI Application
- **Single command deployment**: `npx pastevault up`
- **Integrated backend + frontend** serving
- **Configurable port and host** options
- **Environment variable support**
- **Automatic database migrations**

### Deployment Options
- **npm package distribution** for easy installation
- **Docker containerization** with multi-service compose
- **Development and production** build configurations
- **PostgreSQL and SQLite** database support
- **Environment-specific configurations**

### CLI Commands
- `npx pastevault up` - Start complete application
- `npx pastevault up --port 3000 --host 0.0.0.0` - Custom configuration
- `npx pastevault version` - Version information
- Health check at `/health` endpoint
- Native client: `pastevault put|get|list|status|revoke|audit|token|agent|request|await|secret|run|inject|mcp|login|whoami|logout` (see `docs/cli-reference.md`)

## 🧹 Maintenance & Operations

### Automated Cleanup
- **Scheduled cron jobs** for expired paste removal
- **Configurable cleanup intervals** (default: hourly)
- **Database optimization** through automatic cleanup
- **Graceful error handling** in cleanup operations

### Monitoring & Logging
- **Structured JSON logging** with configurable levels
- **Health check endpoints** for uptime monitoring
- **Error tracking** with detailed stack traces
- **Performance metrics** and request timing

### Development Tools
- **Hot reload** development servers
- **TypeScript compilation** with strict type checking
- **ESLint integration** for code quality
- **Build optimization** for production deployment

## 🌍 Internationalization

### Multi-language Support
- **next-intl integration** for internationalization
- **Configurable locale switching**
- **Translation keys** for UI text
- **Accessible language selection** interface

## 📱 Progressive Web App Features

### Offline Capability
- **Local draft storage** with automatic persistence
- **Client-side encryption** works without network
- **Service worker support** (configurable)
- **Progressive enhancement** for degraded networks

### Performance Optimization
- **Code splitting** for reduced bundle sizes
- **Lazy loading** of heavy components
- **Optimized asset delivery** with Next.js
- **Efficient re-rendering** with React Query caching

## 🔒 Privacy & Compliance

### Data Protection
- **No server-side plaintext storage** - zero-knowledge architecture
- **Minimal metadata collection** (only encrypted content + timestamps)
- **No user accounts required** - anonymous paste creation; accounts are optional (and can be disabled with `DISABLE_AUTH=true`)
- **Automatic data expiration** with configurable retention
- **GDPR-friendly design** with minimal data collection

### Security Best Practices
- **Content Security Policy** headers
- **CORS protection** with configurable origins
- **Rate limiting** to prevent abuse
- **Input validation** and sanitization
- **Secure cookie handling** and session management

---

# 🚀 Future Features & Improvements

*The following sections outline potential enhancements to make PasteVault even more powerful and user-friendly.*

## 🎯 High Priority Features

### User Management & Organization
- **Paste collections/folders** - Organize pastes with custom tags and categories
- **Favorites system** - Bookmark frequently accessed pastes
- **Advanced search functionality** - Filter by date, format, size, tags, and content
- **Paste templates** - Pre-configured formats for common use cases
- **Personal paste analytics** - View statistics for your own pastes

### Enhanced Content Management
- **Version history and revisions** - Track changes with diff viewing between versions
- **Paste forking/branching** - Create derivatives of existing pastes
- **Image paste and preview** - Drag-drop images with inline display
- **Rich text WYSIWYG editor** - Alternative to markdown for non-technical users

### Improved Editor Experience
- **Split-pane markdown editor** - Live preview alongside editing
- **Full-screen editing mode** - Distraction-free writing experience
- **Custom keyboard shortcuts** - User-configurable hotkeys

## 🔧 Medium Priority Features

### Collaboration & Social
- **Comments and annotations** - Discussion threads on specific lines
- **Paste sharing permissions** - Read-only, edit, or comment access levels
- **Activity feeds** - Track changes and interactions on shared pastes
- **@mentions and notifications** - Alert users about relevant paste activity

### API & Integration Enhancements
- **Browser extension** - Quick paste creation from any webpage
- **IDE plugins** - VS Code, JetBrains, and other editor integrations
- **Webhook notifications** - Real-time events for paste creation/updates
- **GraphQL API** - Flexible query interface alongside REST API
- **Bulk operations API** - Efficient handling of multiple pastes
- **Export formats** - PDF, HTML, LaTeX, Word document generation

### Advanced Security Features
- **Multi-factor authentication** - Additional security for password-protected pastes
- **Digital signatures** - Verify paste authenticity and integrity, including sender signatures for shares sealed to an agent (today sealed shares are confidential but not sender-authenticated)
- **OS keychain storage** - Keep agent private keys in the OS keychain instead of `0600` files
- **Advanced key derivation** - Argon2 and scrypt options for password-based encryption
- **Hardware security keys** - WebAuthn support for enhanced authentication
- **Self-destruct triggers** - Custom conditions for automatic paste deletion
- **Steganography options** - Hide paste content within images

## 🌟 Advanced Features

### Privacy-Respectful Analytics & User Retention Measurement
- **Anonymous cohort tracking** - Group users by creation week/month without individual identification
- **Aggregated usage patterns** - System-wide metrics without linking to specific users or IP addresses
- **Content format popularity** - Track most-used languages and formats across all pastes
- **Session-based metrics** - Count unique browser sessions rather than users
- **Return visit patterns** - Measure repeat usage through anonymous browser fingerprinting
- **Paste lifecycle analytics** - Aggregate data on view counts, expiry rates, and burn-after-read usage
- **Geographic insights** - Country-level usage patterns (from HTTP headers) without precise location tracking
- **Performance monitoring** - Real-time system health and response times
- **Retention measurement approaches**:
  - **Browser-local storage tokens** - Generate anonymous session IDs stored only in browser localStorage
  - **Statistical sampling** - Randomly sample a small percentage of sessions for retention analysis
  - **Aggregate cohort analysis** - Track weekly/monthly new vs returning session patterns
  - **Content engagement metrics** - Monitor paste creation frequency and view patterns anonymously
  - **Optional privacy-preserving analytics** - Allow users to opt-in to anonymous usage data collection
- **Privacy-first implementation**:
  - **No cookies or persistent tracking** - Use only session-based measurement
  - **Data aggregation at collection** - Never store individual user paths or behaviors
  - **Automatic data aging** - Purge analytics data after 90 days maximum
  - **Transparent analytics policy** - Clear documentation of what data is collected and why

### Content Intelligence
- **Automatic language detection** - Smart format selection based on content

### Performance & Infrastructure
- **CDN integration** - Global content delivery for faster access
- **Database optimization** - Read replicas and query optimization
- **Redis caching layer** - Improved response times and reduced load
- **Background job processing** - Asynchronous tasks with queue management
- **Horizontal scaling support** - Multi-instance deployment capabilities
- **Load balancing** - Distribute traffic across multiple servers

## 📱 Mobile & Progressive Web App

### Enhanced Mobile Experience
- **Native mobile applications** - iOS and Android apps with full feature parity
- **Advanced offline support** - Service workers for complete offline functionality
- **Push notifications** - Alerts for paste interactions and updates
- **Voice-to-text input** - Speech recognition for hands-free paste creation
- **Camera integration** - OCR for converting physical documents to digital pastes
- **Gesture navigation** - Intuitive touch controls and swipe actions
- **Mobile-specific optimizations** - UI/UX tailored for small screens

## 🏢 Enterprise & Team Features

### Team Collaboration
- **Team workspaces** - Shared environments for organizations
- **Role-based access control** - Granular permissions for different user types
- **SSO integration** - SAML, OAuth, LDAP authentication support
- **Private organizational instances** - Self-hosted solutions for enterprises
- **Custom branding** - White-label options with organization themes
- **Compliance reporting** - GDPR, HIPAA, SOX compliance tools

### Administrative Features
- **Admin dashboard** - System monitoring and user management
- **Content moderation tools** - Review and manage user-generated content
- **Spam detection** - AI-powered filtering of malicious or unwanted content
- **Usage quotas** - Configurable limits per user or organization
- **Data retention policies** - Automated cleanup based on compliance requirements
- **Enterprise backup solutions** - Automated data protection and recovery

## 🔮 Innovative & Experimental Features

### AI & Machine Learning
- **Intelligent paste recommendations** - Suggest relevant pastes based on content
- **Auto-documentation generation** - Generate README files from code pastes
- **Code refactoring suggestions** - AI-powered improvement recommendations
- **Natural language queries** - Search pastes using conversational language
- **Content summarization** - Automatic generation of paste descriptions
- **Translation services** - Multi-language support for international teams

### Integration Ecosystem
- **Code review tool integration** - Connect with GitHub, GitLab, Bitbucket
- **Project management links** - Integration with Jira, Trello, Asana
- **Communication platform hooks** - Slack, Discord, Microsoft Teams integration
- **Documentation platform sync** - Confluence, Notion, GitBook compatibility
- **CI/CD pipeline integration** - Automatic paste creation from build outputs
- **Development workflow tools** - Integration with popular developer tools

### Social & Community Features
- **Public paste galleries** - Showcase interesting or educational content
- **User profiles and following** - Build communities around shared interests
- **Paste contests and challenges** - Gamification for engagement
- **Community moderation** - User-driven content quality management
- **Educational features** - Code review and learning opportunities
- **Open source project showcases** - Highlight community contributions

## 📊 Success Metrics & KPIs

### Product Goals
- **User engagement** - Daily/monthly active users, session duration
- **Content creation** - Pastes created per user, retention rates  
- **Security effectiveness** - Zero data breaches, successful encryption rate
- **Performance benchmarks** - Page load times, API response times
- **User satisfaction** - Net Promoter Score, user feedback ratings
- **Growth metrics** - New user acquisition, viral coefficient