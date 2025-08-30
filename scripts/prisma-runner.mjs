#!/usr/bin/env node

import { execSync } from 'child_process';
import { join } from 'path';
import dotenv from 'dotenv';

dotenv.config();

const provider = process.env.DATABASE_PROVIDER || 'postgresql';

// Use package root if running from NPM package, otherwise use current directory
const packageRoot = process.env.PASTEVAULT_PACKAGE_ROOT || process.cwd();
const schemaFile = provider === 'sqlite' 
  ? join(packageRoot, 'prisma/schema.sqlite.prisma')
  : join(packageRoot, 'prisma/schema.prisma');

const command = process.argv.slice(2).join(' ');

try {
  execSync(`npx prisma ${command} --schema="${schemaFile}"`, {
    stdio: 'inherit',
    env: process.env
  });
} catch (error) {
  console.error(`Error running prisma ${command}:`, error.message);
  process.exit(1);
}
