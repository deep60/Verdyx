# Multi-stage Dockerfile for Verdyx Frontend
# Stage 1: Build the application
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (use npm install as fallback if lockfile was updated)
RUN npm ci || npm install

# Copy source code
COPY . .

# Build the client application (vite build -> dist/)
RUN npm run build

# Bundle the server TypeScript into a single JS file
# tsconfig has noEmit:true so tsc won't produce .js files — use esbuild instead
# - format=esm: package.json has "type":"module" and index.ts uses top-level await
# - banner defines __dirname/__filename which don't exist in ESM output
# - vite + vite.config are loaded dynamically in dev only (server/vite.ts), so
#   they are marked external and never initialized in production.
RUN npx --yes esbuild server/index.ts --bundle --platform=node --format=esm --outfile=dist/server.js \
    --banner:js="import{createRequire as _cr}from'module';import{fileURLToPath as _f}from'url';import{dirname as _d}from'path';const require=_cr(import.meta.url);const __filename=_f(import.meta.url);const __dirname=_d(__filename);" \
    --external:express --external:dotenv \
    --external:vite --external:../vite.config --external:lightningcss \
    --external:@babel/preset-typescript --external:fsevents

# Stage 2: Production image
FROM node:20-alpine

WORKDIR /app

# Install production dependencies only
COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev

# Copy built assets and bundled server from builder
COPY --from=builder /app/dist ./dist

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5000/api/engines', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start the application
CMD ["node", "dist/server.js"]
