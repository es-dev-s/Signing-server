FROM node:20-alpine

# better-sqlite3 requires native compilation tools
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Install dependencies (rebuilt for Linux)
COPY package.json package-lock.json ./
RUN npm ci --production

# Copy application code
COPY server.js database.js ipUtils.js auditOrgAccessProxy.js ./
COPY scripts/ scripts/

EXPOSE 8085

CMD ["node", "server.js"]
