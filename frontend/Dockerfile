FROM node:20-alpine
WORKDIR /app
COPY package.json next.config.mjs ./
RUN npm install
COPY app ./app
EXPOSE 3000
CMD ["npm","run","dev"]
