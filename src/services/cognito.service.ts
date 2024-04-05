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

  public async signInUser(username: string, password: string): Promise<{}> {
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
      return data
    } catch (error: any) {
      throw new Error(`Error signing in user, ${error.message}`)
    }
  }

  public async changePassword(accessToken: string, oldUserPassword: string, newUserPassword: string) {
    try {
      const params = {
        PreviousPassword: oldUserPassword,
        ProposedPassword: newUserPassword,
        AccessToken: accessToken
      }
      const data = await this.cognitoIdentity.changePassword(params).promise()
      console.log(data)
      return true
    } catch (error: any) {
      throw new Error(`Error changing user password, ${error.message}`)
    }
  }

  public async deleteUser(accessToken: string): Promise<boolean> {
    try {
      const params = {
        AccessToken: accessToken
      }
      const data = await this.cognitoIdentity.deleteUser(params).promise()
      return true
    } catch (error: any) {
      throw new Error(`Error deleting user, ${error.message}`);
    }
  }

  public async forgotPassword(username: string): Promise<boolean> {
    try {
      const params = {
        ClientId: this.clientId,
        Username: username,
        SecretHash: this.generateHash(username)
      }
      const data = await this.cognitoIdentity.forgotPassword(params).promise()
      console.log(data)
      return true
    } catch (error: any) {
      throw new Error(`Error resetting user password, ${error.message}`);
    }
  }

  public async confirmNewPassword(username: string, confirmationCode: string, newPassword: string): Promise<boolean> {
    try {
      const params = {
        ClientId: this.clientId,
        ConfirmationCode: confirmationCode,
        Password: newPassword,
        Username: username,
        SecretHash: this.generateHash(username)
      }
      const data = await this.cognitoIdentity.confirmForgotPassword(params).promise()
      console.log(data)
      return true
    } catch (error: any) {
      throw new Error(`Error confirming new password, ${error.message}`);
    }
  }

  public async resendEmailVerificationCode(username: string): Promise<boolean> {
    try{
      const params = {
        ClientId: this.clientId,
        Username: username,
        SecretHash: this.generateHash(username)
      }
      const data = await this.cognitoIdentity.resendConfirmationCode(params).promise()
      console.log(data)
      return true
    } catch (error: any) {
      throw new Error(`Error resending email verification confirmation code, ${error.message}`);
    }
  }

  private generateHash(username: string): string {
    return crypto.createHmac('SHA256', this.secretHash)
      .update(username + this.clientId)
      .digest('base64')
  }
}

