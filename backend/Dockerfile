FROM node:18-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --only=production || npm ci
COPY src ./src
ENV PORT=4000
EXPOSE 4000
CMD ["node","src/server.js"]
