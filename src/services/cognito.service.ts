import AWS from 'aws-sdk';
import crypto from 'crypto'
require('dotenv').config()

export default class CognitoService {
  private config = {
    region: process.env.REGION
  }
  private secretHash: string = process.env.SECRET_HASH!
  private clientId: string = process.env.CLIENT_ID!
  private cognitoIdentity: AWS.CognitoIdentityServiceProvider;

  constructor() {
    this.cognitoIdentity = new AWS.CognitoIdentityServiceProvider(this.config)
  }

  public async signUpUser(username: string, password: string, userAttributes: Array<any>): Promise<boolean> {
    const params = {
      ClientId: this.clientId,
      Password: password,
      Username: username,
      SecretHash: this.generateHash(username),
      UserAttributes: userAttributes
    }
    try {
      const data = await this.cognitoIdentity.signUp(params).promise()
      console.log(data)
      return true
    } catch (error: any) {
      console.log(error)
      throw new Error(`Error signing up user, ${error.message}`)
    }
  }

  public async verifyAccount(username: string, code: string): Promise<boolean> {
    try {
      const params = {
        ClientId: this.clientId,
        ConfirmationCode: code, 
        SecretHash: this.generateHash(username),
        Username: username
      }

      const data = await this.cognitoIdentity.confirmSignUp(params).promise()
      console.log(data)
      return true
    } catch (error: any) {
      console.log(error.message, error)
      throw new Error(`Error verifying user's email, ${error.message}`)
    }
  }

  public async signInUser(username: string, password: string): Promise<boolean> {
    try {
      const params = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: this.clientId,
        AuthParameters: {
          'USERNAME': username,
          'PASSWORD': password,
          'SECRET_HASH': this.generateHash(username)
        }
      }

      const data = await this.cognitoIdentity.initiateAuth(params).promise()
      console.log(data)
      return true
    } catch (error: any) {
      throw new Error(`Error signing in user, ${error.message}`)
    }
  }

  private generateHash(username: string): string {
    return crypto.createHmac('SHA256', this.secretHash)
      .update(username + this.clientId)
      .digest('base64')
  }

  // hashSecret(username: string): string {
  //   return crypto.createHmac('SHA256', this.secretHash)
  //   .update(username + this.clientId)
  //   .digest('base64')  
  // }
}

