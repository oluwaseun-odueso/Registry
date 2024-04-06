import express, { Request, Response } from 'express';
import {OK, UNPROCESSABLE_ENTITY, INTERNAL_SERVER_ERROR, BAD_REQUEST, UNAUTHORIZED} from 'http-status'
import { body, validationResult } from 'express-validator'

import AuthMiddleware from "../middlewares/auth.middleware";
import CognitoService from '../services/cognito.service'

export default class AuthController {
  public path = '/auth';
  public router = express.Router();
  private authMiddleware;

  constructor() {
    this.authMiddleware = new AuthMiddleware()
    this.initRoutes()
  }

  private initRoutes() {
    this.router.post('/signup', this.validateBody('signUp'), this.signUp)
    this.router.post('/signin', this.validateBody('signIn'), this.signIn)
    this.router.post('/verify', this.validateBody("verify"), this.verify)
    this.router.get('/resend-verification-link', this.validateBody('resendVerificationCode'), this.resendEmailVerificationCode)
    this.router.get('/forgot-password', this.validateBody('forgotPassword'), this.forgotPassword)
    this.router.get('/confirm-password', this.validateBody('confirmPassword'), this.confirmPassword)
    this.router.use(this.authMiddleware.verifyToken)
    this.router.get('/change-password', this.validateBody('changePassword'), this.changePassword)
    this.router.delete('/delete-user-account', this.deleteUser)
  }

  async signUp(req: Request, res:Response) {
    try {
      const result = validationResult(req)
      if (!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }

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
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Error signing in user"})    
    }
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

  async resendEmailVerificationCode(req: Request, res: Response) {
    try {
      const result = validationResult(req)

      if(!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }

      const { username } = req.body;
      const cognito = new CognitoService();
      const success = await cognito.resendEmailVerificationCode(username)

      if (!success) return res.status(BAD_REQUEST).json({status: false, message: "Error resending verification code"})

      res.status(OK).json({status: true, message: "Kindly check your email for verification code", success})
    } catch (error: any) {
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Error resending verification code to user"})
    }
  }

  async changePassword(req: Request, res: Response) {
    try {
      const token = req.header('Authorization')
      if(!token) return res.status(UNAUTHORIZED).json({status: false, message: "Please Login to perform operation"})

      const result = validationResult(req)
      if (!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }

      const { oldUserPassword, newUserPassword} = req.body

      const cognito = new CognitoService();
      const success = await cognito.changePassword(token, oldUserPassword, newUserPassword)

      if (!success) return res.status(BAD_REQUEST).json({status: false, message: "Error changing user password"})

      res.status(OK).json({status: true, message: "You have successfully changed your password", success})
    } catch (error: any) {
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Error updating user password"})
    }
  }

  async forgotPassword(req: Request, res: Response) {
    try {
      const result = validationResult(req)
      if (!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }
      const { username} = req.body

      const cognito = new CognitoService();
      const success = await cognito.forgotPassword(username)

      if (!success) return res.status(BAD_REQUEST).json({status: false, message: "Error resending forgot password code"})

      res.status(OK).json({status: true, message: "Check your registered email for a code to complete the process", success})
    } catch (error: any) {
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Error sending forgot password verification code"})
    }
  }

  async confirmPassword(req: Request, res: Response) {
    try {
      const result = validationResult(req)
      if (!result.isEmpty()) {
        return res.status(UNPROCESSABLE_ENTITY).json({status: false, error: result.array()})
      }
      const { username, confirmationCode, newPassword} = req.body

      const cognito = new CognitoService();
      const success = await cognito.confirmNewPassword(username, confirmationCode, newPassword)

      if (!success) return res.status(BAD_REQUEST).json({status: false, message: "Error reseting password"})

      res.status(OK).json({status: true, message: "Password reset successful", success})
    } catch (error: any) {
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Error reseting user password"})
    }
  }

  async deleteUser(req: Request, res: Response) {
    try {
      const token = req.header('Authorization')
      if(!token) return res.status(UNAUTHORIZED).json({status: false, message: "Please Login to perform operation"})

      const cognito = new CognitoService();
      const success = await cognito.deleteUser(token)

      if (!success) return res.status(BAD_REQUEST).json({status: false, message: "Error deleting account"})

      res.status(OK).json({status: true, message: "User account has been deleted", success})
    } catch (error: any) {
      res.status(INTERNAL_SERVER_ERROR).json({status: false, message: "Error deleting user password"})
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
      case 'resendVerificationCode':
        return [
          body('username').notEmpty().isLength({ min: 5})
        ]
      case 'changePassword':
        return [
          body('oldUserPassword').notEmpty(),
          body('newUserPassword').notEmpty()
        ]
      case 'forgotPassword':
        return [
          body('username').notEmpty().isLength({ min: 5}),
        ]
      case 'confirmPassword':
        return [
          body('newPassword').exists().isLength({ min: 8}),
          body('username').notEmpty().isLength({ min: 5}),
          body('confirmationCode').notEmpty().isString().isLength({min: 6, max: 6})
        ]
      default: 
        return []
    }
  }
}

