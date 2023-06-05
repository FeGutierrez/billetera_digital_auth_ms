FROM node:14

WORKDIR /app

RUN npm install express mongoose bcrypt jsonwebtoken

COPY . /app

EXPOSE 3000

CMD ["node", "server.js"]