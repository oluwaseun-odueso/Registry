import {Request, Response, NextFunction} from 'express';
import jwt from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';
import fetch from 'node-fetch';
import { OK, UNAUTHORIZED } from 'http-status';
import dotenv from 'dotenv';
dotenv.config();

// require('dotenv').config();

let pems: { [key: string]: any }  = {}


export default class AuthMiddleware {
  private poolRegion: string = process.env.REGION!
  private userPoolId: string = process.env.USER_POOL_ID!

  constructor() {
    this.setUp()
  }

  verifyToken(req: Request, res: Response, next: NextFunction) {
    try {
      const token = req.header('Authorization')

      if(!token) return res.status(UNAUTHORIZED).json({status: false, message: "Please Login to perform operation"})

      let decodedToken = jwt.decode(token, { complete: true });
      if (decodedToken === null) return res.status(UNAUTHORIZED).json({status: false, message: "Invalid token"})

      let kid = decodedToken.header.kid!;
      let pem = pems[kid]
      if (!pem) {
        res.status(401).end()
        return
      }
      jwt.verify(token, pem, (err: any, payload: any) => {
        if (err) {
          res.status(UNAUTHORIZED).end()
          return
        } next()
      })
    } catch (error: any) {
      throw new Error(``)
    }
  }

  private async setUp() {
    try{
      const URL = `https://cognito-idp.${this.poolRegion}.amazonaws.com/${this.userPoolId}/.well-known/jwks.json`
      const response = await fetch(URL);

      if(response.status !== OK) {
        throw new Error('Request not successful')
      }
      const data: any = await response.json()
      const keys: any = data.keys
      for (let i = 0; i < keys.length; i++) {
        const key_id = keys[i].kid;
        const modulus = keys[i].n;
        const exponent = keys[i].e;
        const key_type = keys[i].kty;
        const jwk = { kty: key_type, n: modulus, e: exponent };
        const pem = jwkToPem(jwk);
        pems[key_id] = pem;
      }
    } catch (error: any) {
      throw new Error(`Error fetching jwks, ${error.message}`)
    }
  }
}