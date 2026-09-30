# Node 20 went end-of-life in April 2026; 22 is the current LTS.
FROM node:22-alpine AS build
WORKDIR /src
# The lockfile is copied so `npm ci` installs the exact resolved tree. Without
# it every build re-resolved the ^ ranges, which meant two builds of the same
# commit could ship different dependency versions — and a compromised patch
# release would land silently.
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /src/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
