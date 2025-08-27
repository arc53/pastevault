# Stage 1: Build the application
FROM node:22-slim AS builder

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the application source code
COPY . .

# Build the application
RUN npm run build

# Stage 2: Create the production image
FROM node:22-slim

WORKDIR /app

# Copy package files and install production dependencies
COPY package*.json ./
RUN npm install --production

# Copy the built application from the builder stage
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json

# Expose the port the app runs on
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
