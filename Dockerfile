FROM node:alpine
WORKDIR /usr/epr-server
COPY . .
RUN npm install

CMD ["node",  "src/index.js"]