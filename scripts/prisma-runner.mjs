#!/usr/bin/env node

import { execSync } from 'child_process';
import dotenv from 'dotenv';

dotenv.config();

const provider = process.env.DATABASE_PROVIDER || 'postgresql';

const schemaFile = provider === 'sqlite' ? 'prisma/schema.sqlite.prisma' : 'prisma/schema.prisma';

const command = process.argv.slice(2).join(' ');

try {
  execSync(`npx prisma ${command} --schema=${schemaFile}`, {
    stdio: 'inherit',
    env: process.env
  });
} catch (error) {
  console.error(`Error running prisma ${command}:`, error.message);
  process.exit(1);
}
