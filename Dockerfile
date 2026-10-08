FROM node:24-alpine

ENV NODE_ENV=production \
    AUTH0_MOCK_HOST=0.0.0.0 \
    AUTH0_MOCK_PORT=4400 \
    AUTH0_MOCK_TLS_DIR=/certs

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY bin/ ./bin/
COPY src/ ./src/

# /certs holds the generated CA, server certificate and JWT signing key (mount it to keep them across
# restarts and to share the CA with other containers); /config is a convenient mount for seed/pin files.
RUN mkdir -p /certs /config && chown -R node:node /certs /config /app
VOLUME ["/certs"]
USER node

EXPOSE 4400
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=10 \
  CMD node -e "process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';const p=process.env.AUTH0_MOCK_TLS==='off'?'http':'https';fetch(p+'://127.0.0.1:'+(process.env.AUTH0_MOCK_PORT||4400)+'/__mock/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"

CMD ["node", "bin/auth0-mock.ts"]
