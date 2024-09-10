FROM node:latest

WORKDIR /app

COPY package*.json ./

RUN npm isntall

COPY . .

CMD ["npm", "Start"]