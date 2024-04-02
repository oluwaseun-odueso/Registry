import express, { Request, Response } from 'express';
import {OK, UNPROCESSABLE_ENTITY, INTERNAL_SERVER_ERROR, BAD_REQUEST} from 'http-status'
import { body, validationResult } from 'express-validator'

import CognitoService from '../services/cognito.service'

export default class AuthController {
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

      if (!success) return res.status(BAD_REQUEST).json({status: false, message: "Invalid signup payload"})
      
      res.status(OK).json({status: true, message: "Account created successfully"})
    } catch (error: any) {
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Error signing up user"})
    }
  }

  async signIn(req: Request, res:Response) {
    try {
      const result = validationResult(req)
      if (!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }

      const { username, password} = req.body

      const cognito = new CognitoService();
      const success = await cognito.signInUser(username, password)

      if (!success) return res.status(BAD_REQUEST).json({status: false, message: "Error signing in user"})

      res.status(OK).json({status: true, message: "You are signed in", success})
    } catch (error: any) {
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Error signing in user"})    }
  }

  async verify(req: Request, res:Response) {
    try {
      const result = validationResult(req)
      if (!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }

      const { username, code } = req.body;
      console.log('Verify body is valid')

      const cognito = new CognitoService();
      const success = await cognito.verifyAccount(username, code)

      if (!success) return res.status(UNPROCESSABLE_ENTITY).json({status: false, message: "Invalid details"})

      res.status(OK).json({status: false, message: "Email verification complete"})

    } catch (error: any) {
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Error verifying user's email"})
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

