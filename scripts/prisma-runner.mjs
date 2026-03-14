#!/usr/bin/env node

import { execSync } from 'child_process';
import { join } from 'path';
import dotenv from 'dotenv';

dotenv.config();

// Use package root if running from NPM package, otherwise use current directory
const packageRoot = process.env.PASTEVAULT_PACKAGE_ROOT || process.cwd();
const configFile = join(packageRoot, 'prisma.config.js');

const command = process.argv.slice(2).join(' ');

try {
  execSync(`npx prisma ${command} --config="${configFile}"`, {
    stdio: 'inherit',
    cwd: packageRoot,
    env: process.env
  });
} catch (error) {
  console.error(`Error running prisma ${command}:`, error.message);
  process.exit(1);
}
