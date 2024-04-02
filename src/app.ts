import express from 'express';
import { Application } from 'express';
import { RequestHandler, ParamsDictionary } from 'express-serve-static-core';
import { ParsedQs } from 'qs';

export default class App {
  public app: Application
  public port: number

  constructor (appInit: { port: number; middlewares: any;controllers: any}){
    this.app = express()
    this.port = appInit.port;
    this.middlewares(appInit.middlewares)
    this.routes(appInit.controllers)
  }

  private routes(controllers: any[]) {
    controllers.forEach(controller => {
      this.app.use(controller.path, controller.router)
    });
  }

  private middlewares(middlewares: any[]) {
    middlewares.forEach(middleware => {
      this.app.use(middleware)
    });
  }

  public listen () {
    this.app.listen(this.port, () => {
      console.log(`App has started on port ${this.port}`)
    })
  }
}

