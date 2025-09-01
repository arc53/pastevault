#!/usr/bin/env node

// Copy this file to dist/bin/cli.js when building

const { Command } = require('commander')
const path = require('path')
const { spawn } = require('child_process')
const { existsSync, writeFileSync } = require('fs')
const chalk = require('chalk')

const program = new Command()

program
  .name('pastevault')
  .description('Simple paste sharing tool using Node and SQLite')
  .version('1.0.5')

program
  .command('up')
  .description('Start the PasteVault server with frontend')
  .option('-p, --port <port>', 'Port for the main server (redirects to frontend)', '3000')
  .option('--backend-port <port>', 'Port for the backend server', '3001')
  .option('--frontend-port <port>', 'Port for the frontend server', '3002')
  .option('--provider <provider>', 'Database provider (sqlite|postgresql)', 'sqlite')
  .option('--database-url <url>', 'Database connection URL')
  .option('--no-frontend', 'Start only backend server without frontend')
  .option('--detach', 'Run in background (daemon mode)')
  .action(async (options) => {
    const { port, backendPort, frontendPort, provider, databaseUrl, noFrontend, detach } = options

    console.log(chalk.blue('🚀 Starting PasteVault...'))

    // Find project root - check if running from NPM package or local development
    let projectRoot
    const currentDir = process.cwd()
    
    // If we're in an NPM global install, __dirname points to global node_modules
    if (__dirname.includes('node_modules')) {
      projectRoot = path.resolve(__dirname, '..', '..')
    } else {
      // Running from local development
      projectRoot = path.resolve(__dirname, '..', '..')
    }

    // Create .env file in current working directory
    const envPath = path.join(currentDir, '.env')
    if (!existsSync(envPath)) {
      console.log(chalk.yellow('📝 Creating .env configuration...'))
      const dbUrl = databaseUrl || (provider === 'sqlite' ? 'file:./pastevault.db' : 'postgresql://localhost:5432/pastevault')
      const envContent = `# PasteVault Configuration
DATABASE_URL="${dbUrl}"
DATABASE_PROVIDER="${provider}"
PORT="${backendPort}"
NODE_ENV="production"
CORS_ORIGIN="http://localhost:${frontendPort}"
RATE_LIMIT_MAX="100"
RATE_LIMIT_WINDOW_MS="60000"
MAX_PASTE_SIZE_BYTES="1048576"
CLEANUP_INTERVAL_MINUTES="60"
PASTEVAULT_CLI_MODE="true"
PASTEVAULT_MAIN_PORT="${port}"
`
      writeFileSync(envPath, envContent)
    }

    // Check if we need to install frontend dependencies and build
    const frontendDir = path.join(projectRoot, 'frontend')
    const frontendNodeModules = path.join(frontendDir, 'node_modules')
    
    if (existsSync(frontendDir) && !noFrontend) {
      // Install dependencies if needed
      if (!existsSync(frontendNodeModules)) {
        console.log(chalk.yellow('📦 Installing frontend dependencies...'))
        const npmInstall = spawn('npm', ['install', '--include=dev'], {
          cwd: frontendDir,
          stdio: 'inherit'
        })

        await new Promise((resolve, reject) => {
          npmInstall.on('close', (code) => {
            if (code === 0) {
              resolve(undefined)
            } else {
              reject(new Error(`Frontend dependency installation failed with code ${code}`))
            }
          })
          npmInstall.on('error', reject)
        })
      }

      // Always build frontend for fresh start
      console.log(chalk.yellow('🔨 Building frontend...'))
      const buildProcess = spawn('npm', ['run', 'build'], {
        cwd: frontendDir,
        stdio: 'inherit'
      })

      await new Promise((resolve, reject) => {
        buildProcess.on('close', (code) => {
          if (code === 0) {
            resolve(undefined)
          } else {
            console.log(chalk.red(`❌ Frontend build failed with exit code ${code}`))
            console.log(chalk.yellow('💡 This might be due to missing dependencies or TypeScript errors.'))
            reject(new Error(`Frontend build failed with code ${code}`))
          }
        })
        buildProcess.on('error', (err) => {
          console.log(chalk.red(`❌ Frontend build process error: ${err.message}`))
          reject(err)
        })
      })
    }

    // Initialize database if needed
    console.log(chalk.yellow('📦 Setting up database...'))
    const prismaRunner = spawn('node', [path.join(projectRoot, 'scripts', 'prisma-runner.mjs'), 'db', 'push'], {
      cwd: currentDir,
      stdio: 'inherit',
      shell: true,
      env: { 
        ...process.env, 
        DATABASE_PROVIDER: provider,
        PASTEVAULT_PACKAGE_ROOT: projectRoot
      }
    })

    await new Promise((resolve, reject) => {
      prismaRunner.on('close', (code) => {
        if (code === 0) {
          resolve(undefined)
        } else {
          reject(new Error(`Database setup failed with code ${code}`))
        }
      })
      prismaRunner.on('error', reject)
    })

    console.log(chalk.green('✅ Database setup complete'))

    // Start backend server
    console.log(chalk.yellow('🔧 Starting backend server...'))
    const backendProcess = spawn('node', [path.join(projectRoot, 'dist', 'index.js')], {
      cwd: currentDir,
      stdio: detach ? 'ignore' : 'inherit',
      detached: detach,
      env: { 
        ...process.env, 
        PASTEVAULT_CLI_MODE: 'true', 
        PORT: backendPort.toString(),
        DATABASE_PROVIDER: provider
      }
    })

    // Start frontend if requested
    let frontendProcess = null
    if (!noFrontend && existsSync(frontendDir)) {
      console.log(chalk.yellow('🌐 Starting frontend server...'))
      
      frontendProcess = spawn('npm', ['run', 'start', '--', '-p', frontendPort.toString()], {
        cwd: frontendDir,
        stdio: detach ? 'ignore' : 'inherit',
        detached: detach,
        env: { ...process.env }
      })

      console.log(chalk.green(`✅ Frontend server starting on http://localhost:${frontendPort}`))
    }

    if (detach) {
      backendProcess.unref()
      if (frontendProcess) frontendProcess.unref()
      
      console.log(chalk.green(`✅ PasteVault running in background`))
      console.log(chalk.blue(`🌍 Access at http://localhost:${port}`))
      console.log(chalk.yellow(`Use 'pastevault down' to stop`))
      return
    }

    console.log(chalk.green(`✅ Backend server started on http://localhost:${backendPort}`))
    if (!noFrontend && existsSync(frontendDir)) {
      console.log(chalk.green(`✅ Frontend available at http://localhost:${frontendPort}`))
      console.log(chalk.blue(`🌍 Main access: http://localhost:${port} (redirects to frontend)`))
    } else {
      console.log(chalk.blue(`🌍 Backend API: http://localhost:${backendPort}`))
    }

    // Handle graceful shutdown
    const cleanup = () => {
      console.log(chalk.red('\n🛑 Shutting down PasteVault...'))
      backendProcess.kill()
      if (frontendProcess) {
        frontendProcess.kill()
      }
      process.exit(0)
    }

    process.on('SIGINT', cleanup)
    process.on('SIGTERM', cleanup)

    // Wait for processes
    await Promise.all([
      new Promise((resolve) => backendProcess.on('close', resolve)),
      frontendProcess ? new Promise((resolve) => frontendProcess.on('close', resolve)) : Promise.resolve()
    ])
  })

program
  .command('down')
  .description('Stop background PasteVault processes')
  .action(() => {
    console.log(chalk.blue('🛑 Stopping PasteVault...'))
    
    const { execSync } = require('child_process')
    try {
      // Kill processes by name (works on Unix-like systems)
      execSync('pkill -f "pastevault"', { stdio: 'ignore' })
      execSync('pkill -f "node.*dist/index.js"', { stdio: 'ignore' })
      console.log(chalk.green('✅ PasteVault stopped'))
    } catch (error) {
      console.log(chalk.yellow('⚠️  No running PasteVault processes found'))
    }
  })

program
  .command('status')
  .description('Check if PasteVault is running')
  .action(() => {
    console.log(chalk.blue('📊 Checking PasteVault status...'))
    
    const { execSync } = require('child_process')
    try {
      const result = execSync('pgrep -f "node.*dist/index.js"', { encoding: 'utf8' })
      if (result.trim()) {
        console.log(chalk.green('✅ PasteVault is running'))
        console.log(chalk.gray(`Process ID: ${result.trim()}`))
      } else {
        console.log(chalk.yellow('⚠️  PasteVault is not running'))
      }
    } catch (error) {
      console.log(chalk.yellow('⚠️  PasteVault is not running'))
    }
  })

program
  .command('install')
  .description('Install PasteVault globally via npm')
  .action(() => {
    console.log(chalk.blue('📦 Installing PasteVault globally...'))
    console.log(chalk.yellow('Run: npm install -g pastevault'))
    console.log(chalk.green('Then use: npx pastevault up'))
  })

program.parse()
