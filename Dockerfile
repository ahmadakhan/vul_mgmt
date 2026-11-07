FROM node:26-alpine3.22 AS build
RUN apk upgrade --no-cache
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run lint && npm run build

FROM node:26-alpine3.22 AS runtime
ENV NODE_ENV=production PORT=8080
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
RUN apk upgrade --no-cache && apk add --no-cache chromium
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force \
	&& rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
	&& rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/server-dist ./server-dist
RUN mkdir -p /var/lib/vulnstream/deadletters /var/lib/vulnstream/ml && chown -R node:node /var/lib/vulnstream
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD node -e "fetch('http://127.0.0.1:8080/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","server-dist/main.js"]
