import AWS from 'aws-sdk';
import crypto from 'crypto'
require('dotenv').config()

class CognitoService {
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
      return false
    }
  }

  private generateHash(username: string): string {
    return crypto.createHmac('SHA256', this.secretHash)
      .update(username + this.clientId)
      .digest('base64')
  }
}

export default CognitoService;