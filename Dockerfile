# syntax=docker/dockerfile:1
# ---- build stage ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# ---- production stage ----
FROM node:22-alpine AS production
LABEL org.opencontainers.image.title="password-strength-service"
LABEL org.opencontainers.image.description="NIST SP 800-63B compliant password strength microservice"

# Drop to a non-root user — required for HIPAA/FedRAMP container hardening.
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app

# Install only production dependencies.
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy the built frontend (served by Express in production mode).
COPY --from=build /app/dist ./dist

# Copy the server source (ESM, no transpilation needed for Node 22).
COPY server/ ./server/

USER appuser
EXPOSE 4000

ENV NODE_ENV=production
ENV PORT=4000

CMD ["node", "server/index.js"]
