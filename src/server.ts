import App from './app';

import HomeController from './controllers/home.controller';
import AuthController from './controllers/auth.controller';

import bodyParser from "body-parser";

const app = new App({
  port: 3000,
  controllers: [
    new HomeController(),
    new AuthController(),
  ],
  middlewares: [
    bodyParser.json(),
    bodyParser.urlencoded({extended: true})
  ]
})

app.listen()