# Stage 1: Build the application
FROM node:24-slim AS builder

WORKDIR /app

# Install openssl
RUN apt-get update -y && apt-get install -y openssl

# Copy package files and install dependencies
COPY package*.json ./
# Ensure prisma schema is present for postinstall
COPY prisma ./prisma/
# Select Postgres schema inside container to keep local dev (sqlite) unaffected
ARG DATABASE_PROVIDER=postgresql
ENV DATABASE_PROVIDER=$DATABASE_PROVIDER
RUN if [ "$DATABASE_PROVIDER" = "postgresql" ]; then cp prisma/schema.postgres.prisma prisma/schema.prisma; fi
RUN npm install


# Generate prisma client
RUN npx prisma generate

# Copy the rest of the application source code
COPY . .

# Build the application
RUN npm run build

# Stage 2: Create the production image
FROM node:24-slim

WORKDIR /app

# Install openssl
RUN apt-get update -y && apt-get install -y openssl

# Copy package files and install production dependencies
COPY package*.json ./
# Ensure prisma schema is present for postinstall
COPY prisma ./prisma
# Select Postgres schema inside container to keep local dev (sqlite) unaffected
ARG DATABASE_PROVIDER=postgresql
ENV DATABASE_PROVIDER=$DATABASE_PROVIDER
RUN if [ "$DATABASE_PROVIDER" = "postgresql" ]; then cp prisma/schema.postgres.prisma prisma/schema.prisma; fi
# Use deterministic installs and omit devDependencies for smaller image
RUN npm install --omit=dev

# Copy the built application from the builder stage
COPY --from=builder /app/dist ./dist
# Include runtime scripts for Prisma in container only (does not affect local dev)
COPY scripts ./scripts

# Expose the port the app runs on
EXPOSE 3001

# Start the application (ensure DB schema is applied first)
CMD ["/bin/sh", "-c", "node scripts/prisma-runner.mjs db push && npm start"]
