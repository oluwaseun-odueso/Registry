import express, { Request, Response } from 'express';
import {OK, UNPROCESSABLE_ENTITY, INTERNAL_SERVER_ERROR} from 'http-status'
import { body, validationResult } from 'express-validator'

import CognitoService from '../services/cognito.service'

class AuthController {
  public path = '/auth';
  public router = express.Router();

  constructor() {
    this.initRoutes()
  }

  private initRoutes() {
    this.router.post('/signup', this.validateBody('signUp'), this.signUp)
    this.router.post('/signin', this.validateBody('signIn'), this.signIn)
    this.router.post('/verify', this.validateBody("verify"), this.verify)
  }

  async signUp(req: Request, res:Response) {
    try {
      const result = validationResult(req)
      if (!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }
      console.log('Signup body is valid')

      const {username, name, password, email, gender, birthdate} = req.body;
      let userAttr = []
      userAttr.push({ Name: 'email', Value: email});
      userAttr.push({ Name: 'birthdate', Value: birthdate.toString()});
      userAttr.push({ Name: 'gender', Value: gender});

      userAttr.push({ Name: 'name', Value: name});

      const cognito = new CognitoService();

      const success = await cognito.signUpUser(username, password, userAttr)
      if (success) res.status(OK).json({status: true, message: "Account created successfully"})

    } catch (error: any) {
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Could not complete signup"})
    }
  }

  signIn(req: Request, res:Response) {
    try {
      const result = validationResult(req)
      if (!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }
      console.log('Signin body is valid')
    } catch (error: any) {
      
    }
  }

  verify(req: Request, res:Response) {
    try {
      const result = validationResult(req)
      if (!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }
      console.log('Verify body is valid')
    } catch (error: any) {
      
    }
  }

  private validateBody(type: string) {
    switch (type) {
      case 'signUp':
        return [
          body('username').notEmpty().isLength({min: 5}),
          body('name').notEmpty().isString(),
          body('email').notEmpty().normalizeEmail().isEmail(),
          body('password').isString().isLength({ min: 8}),
          body('birthdate').exists().isISO8601(),
          body('gender').notEmpty().isString(),
        ]
      case 'signIn':
        return [
          body('username').notEmpty().isLength({min: 5}),
          body('password').isString().isLength({ min: 8}),
        ]
      case 'verify':
        return [
          body('username').notEmpty().isLength({min: 5}),
          body('code').notEmpty().isString().isLength({min: 6, max: 6})
        ]
      case 'forgotPassword':
        return [
          body('username').notEmpty().isLength({ min: 5}),
        ]
      case 'confirmPassword':
        return [
          body('password').exists().isLength({ min: 8}),
          body('username').notEmpty().isLength({ min: 5}),
          body('code').notEmpty().isString().isLength({min: 6, max: 6})
        ]
      default: 
        return []
    }
  }
}

export default AuthController;