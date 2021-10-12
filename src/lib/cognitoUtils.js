import { CognitoAuth } from 'amazon-cognito-auth-js/dist/amazon-cognito-auth'
import { CognitoUserPool } from 'amazon-cognito-identity-js'
import appConfig from '../config/app-config.json'
import AWS from 'aws-sdk/global'
import moment from 'moment'
import {
  config as AWSConfig
} from 'aws-sdk'

const AWSRegion = appConfig.region
AWSConfig.region = AWSRegion
export { AWSRegion, AWSConfig }


// Creates a CognitoAuth instance
const createCognitoAuth = () => {
    const appWebDomain = appConfig.userPoolBaseUri.replace('https://', '').replace('http://', '')
    const auth = new CognitoAuth({
      UserPoolId: appConfig.userPool,
      ClientId: appConfig.clientId,
      AppWebDomain: appWebDomain,
      TokenScopesArray: appConfig.tokenScopes,
      RedirectUriSignIn: appConfig.callbackUri,
      RedirectUriSignOut: appConfig.signoutUri
    })
    return auth
  }

  // Creates a CognitoUser instance
const createCognitoUser = () => {
    const pool = createCognitoUserPool()
    return pool.getCurrentUser()
  }
  
  // Creates a CognitoUserPool instance
  const createCognitoUserPool = () => new CognitoUserPool({
    UserPoolId: appConfig.userPool,
    ClientId: appConfig.clientId
  })
  
  // Get the URI of the hosted sign in screen
  const getCognitoSignInUri = () => {
    const signinUri = `${appConfig.userPoolBaseUri}/login?response_type=code&client_id=${appConfig.clientId}&redirect_uri=${appConfig.callbackUri}`
    return signinUri
  }

  // Parse the response from a Cognito callback URI (assumed a token or code is in the supplied href). Returns a promise.
const parseCognitoWebResponse = (href) => {
    return new Promise((resolve, reject) => {
      const auth = createCognitoAuth()
      // userHandler will trigger the promise
      auth.userhandler = {
        onSuccess: function (result) {
          resolve(result)
        },
        onFailure: function (err) {
          reject(new Error('Failure parsing Cognito web response: ' + err))
        }
      }
      auth.parseCognitoWebResponse(href)
    })
  }
  
  // Gets a new Cognito session. Returns a promise.
  const getCognitoSession = () => {
    return new Promise((resolve, reject) => {
      const cognitoUser = createCognitoUser()
      cognitoUser.getSession((err, result) => {
        if (err || !result) {
          reject(new Error('Failure getting Cognito session: ' + err))
          return
        }
        // Resolve the promise with the session credentials
        console.debug('Successfully got session: ' + JSON.stringify(result))
        // Add the User's Id Token to the Cognito credentials login map.
        AWS.config.credentials = new AWS.CognitoIdentityCredentials({
          IdentityPoolId: appConfig.IdentityPoolId,
          Logins: {
              'cognito-idp.us-east-2.amazonaws.com/us-east-2_Fkvfsx7UR': result.getIdToken().getJwtToken()
          }
        })
        AWS.config.getCredentials((err) => {
          if (err) {
              console.log(err);
          } else {
            
            const method = "GET"
            const service = "execute-api"
            const host = "u6bkhgokv3.execute-api.us-east-2.amazonaws.com"
            const region = "us-east-2"
            const accessKeyId = AWS.config.credentials.accessKeyId
            const secretAccessKey = AWS.config.credentials.secretAccessKey
            const sessionToken = AWS.config.credentials.sessionToken
            var crypto = require("crypto");
            var date = moment().utc()
            var amzdate = moment(date).format("YYYYMMDDTHHmmss[Z]")
            var datestamp = moment(date).format('YYYYMMDD')
            console.log(datestamp)
          
            function sign(key, msg) {
              return crypto.createHmac('sha256', key).update(msg).digest()
            }
          
            function getSignatureKey(key, dateStamp, regionName, serviceName) {
                var kDate = sign(("AWS4" + key), dateStamp);
                var kRegion = sign(kDate, regionName);
                var kService = sign(kRegion, serviceName);
                var kSigning = sign(kService,"aws4_request", );
                return kSigning;
            }
          
            var coanical_uri = "/prod/phc"
            var coanical__querystring = ""
            var coanical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n' + 'x-amz-security-token:' + sessionToken + "\n"
            var signed_headers = 'host;x-amz-date;x-amz-security-token'
            var payload_hash = crypto.createHash("sha256").update("").digest('hex')
            var canonical_request = method + '\n' + coanical_uri + '\n' + coanical__querystring + '\n' + coanical_headers + '\n' + signed_headers + '\n' + payload_hash
         console.log(canonical_request)
            var algorithm = 'AWS4-HMAC-SHA256'
            var credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
            var string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  crypto.createHash("sha256").update(canonical_request).digest("hex")
          
            console.log(string_to_sign)
          
            var signing_key = getSignatureKey(secretAccessKey, datestamp, region, service)
            var signature = crypto.createHmac("sha256", signing_key).update(string_to_sign).digest("hex")
          
            const authorization_header = algorithm + ' ' + 'Credential=' + accessKeyId + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature 
          console.log(signing_key)
          console.log(signature)
          console.log(authorization_header)
          console.log(signed_headers)
            const session = {
              credentials: {
                accessToken: result.accessToken.jwtToken,
                idToken: result.idToken.jwtToken,
                refreshToken: result.refreshToken.token,
                sessionToken: AWS.config.credentials.sessionToken,
                auth_header: authorization_header,
                amzdate: amzdate,
                accessKeyId: accessKeyId,
                secretAccessKey: secretAccessKey
              },
              user: {
                userName: result.idToken.payload['cognito:username'],
                email: result.idToken.payload.email
              }
            }

            resolve(session)
            console.log(session)
          }
        });
      })
    })
  }

// Sign out of the current session (will redirect to signout URI)
const signOutCognitoSession = () => {
  const auth = createCognitoAuth()
  auth.signOut()
}

const cognitoId = {
    createCognitoAuth,
    createCognitoUser,
    createCognitoUserPool,
    getCognitoSession,
    getCognitoSignInUri,
    parseCognitoWebResponse,
    signOutCognitoSession
  }

export default cognitoId