# Stage 1: Build the application
FROM node:22-slim AS builder

WORKDIR /app

# Install openssl
RUN apt-get update -y && apt-get install -y openssl

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy prisma schema
COPY prisma ./prisma/

# Generate prisma client
RUN npx prisma generate

# Copy the rest of the application source code
COPY . .

# Build the application
RUN npm run build

# Stage 2: Create the production image
FROM node:22-slim

WORKDIR /app

# Install openssl
RUN apt-get update -y && apt-get install -y openssl

# Copy package files and install production dependencies
COPY package*.json ./
RUN npm install --production

# Copy the built application from the builder stage
COPY --from=builder /app/dist ./dist

# Copy prisma schema and client
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

# Expose the port the app runs on
EXPOSE 3001

# Start the application
CMD ["npm", "start"]
