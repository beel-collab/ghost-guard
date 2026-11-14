FROM node:22-alpine
WORKDIR /app
COPY src ./src
COPY sidecar/server.mjs ./sidecar/server.mjs
ENV NODE_ENV=production
ENV PORT=8787
EXPOSE 8787
CMD ["node", "sidecar/server.mjs"]
