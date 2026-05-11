FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# Production image
FROM node:20-alpine

RUN addgroup -S verifiedtrust && adduser -S verifiedtrust -G verifiedtrust

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist

RUN chown -R verifiedtrust:verifiedtrust /app

USER verifiedtrust

ENTRYPOINT ["node", "/app/dist/cli/index.js"]
