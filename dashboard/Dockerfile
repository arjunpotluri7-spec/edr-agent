# Build the static dashboard, then serve it with unprivileged nginx (listens on 8080).
FROM node:22.23.2-alpine AS build
WORKDIR /src
COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund
COPY index.html tsconfig.json vite.config.ts eslint.config.js ./
COPY src/ src/
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.30.4-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=6 CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
