import express, { Request, Response } from 'express';
import AuthMiddleware from '../middlewares/auth.middleware';

export default class ProtectedController {
  public path = '/protected'
  public router = express.Router()
  private authMiddleware;

  constructor() {
    this.authMiddleware = new AuthMiddleware();
    this.initRoutes()
  }

  public initRoutes() {
    this.router.use(this.authMiddleware.verifyToken)
    this.router.get('/secret', this.secret)
  }

  private async secret(req: Request, res: Response) {
    res.send({status: true, message: "You now have access"})
  }
}