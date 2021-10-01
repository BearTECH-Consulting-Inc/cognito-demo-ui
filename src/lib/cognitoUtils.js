import { CognitoAuth } from 'amazon-cognito-auth-js/dist/amazon-cognito-auth'
import { CognitoUserPool } from 'amazon-cognito-identity-js'
import appConfig from '../config/app-config.json'
import {
  config as AWSConfig,
  CognitoIdentityCredentials,
} from 'aws-sdk'

const AWSRegion = appConfig.region
AWSConfig.region = AWSRegion
export { AWSRegion, AWSConfig, CognitoIdentityCredentials }

/* Config for CognitoID */
const config = {
  identityPool: process.env.REACT_APP_COGNITO_IDENTITY_POOL,
  userPool: {
    UserPoolId: "us-east-2_Fkvfsx7UR",
    ClientId: "38jnlb2fmqm4530dtoip66j415"
  }
}

// Gets user attributes based on the passed cognitoUser
const getUserAttributes = user => {
  return user.getUserAttributes((err, result) => {
    if (err) {
      alert(err)
      return
    }
    return result
  })
}
const getUserPool = () => new CognitoUserPool()
// // The primary method for verifying/starting a CoginotID session
// const verifySession = ({ props, username }) => {
//   const poolUrl = `cognito-idp.${AWSRegion}.amazonaws.com/${
//     config.userPool.UserPoolId
//   }`

// Gets a cognito user
const getCognitoUser = user => {
  const pool = getUserPool()
  return pool.getCurrentUser()
}

  /* You don't have to do this, but I am so I can get the user's name from the parsed JWT token so I don't have
  to call getUserAttributes after the session as been started. */
  const cognitoUser = getCognitoUser()
  let name
  const poolUrl = `cognito-idp.${AWSRegion}.amazonaws.com/${appConfig.userPool}`
    /** Get a new session and set it in the AWS config */
    cognitoUser.getSession((err, result) => {
      console.log(err, result)
      if (result) {
        name = result.idToken.payload.given_name
        AWSConfig.credentials = new CognitoIdentityCredentials({
          IdentityPoolId: config.identityPool,
          Logins: {
            [poolUrl]: result.idToken.jwtToken
          }
        })
      }
    })

      /* Refresh the temporary token */
//   AWSConfig.credentials.refresh(err => {
//     if (err) {
//       console.error('Failed To Login To CognitoID:', err)
//       props.history.push('/', {
//         error: 'Failed to refresh your session. Please login again.'
//       })
//     } else {
//       props.storeSession({
//         token,
//         name
//       })
//     }
//   })
// }

// Creates a CognitoAuth instance
const createCognitoAuth = () => {
  const appWebDomain = appConfig.userPoolBaseUri.replace('https://', '').replace('http://', '')
  const auth = new CognitoAuth({
    UserPoolId: appConfig.userPool,
    ClientId: appConfig.clientId,
    // identityPoolId: appConfig.IdentityPoolId,
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
    const cognitoUser = getCognitoUser()
    cognitoUser.getSession((err, result) => {
      if (err || !result) {
        reject(new Error('Failure getting Cognito session: ' + err))
        return
      }
      const session = {
        credentials: {
          accessToken: result.accessToken.jwtToken,
          idToken: result.idToken.jwtToken,
          refreshToken: result.refreshToken.token,
          accessKeyId: AWSConfig.credentials.accessKeyId
          // secretAccessKeyId: creds.params.secretAccessKeyId,
        },
        user: {
          userName: result.idToken.payload['cognito:username'],
          email: result.idToken.payload.email
        }
      }
      console.log(session)
      resolve(session)
      // Resolve the promise with the session credentials
      console.debug('Successfully got session: ' + JSON.stringify(result))

			// Add the User's Id Token to the Cognito credentials login map.
			AWSConfig.credentials = new CognitoIdentityCredentials({
				IdentityPoolId: 'us-east-2:997dbcf7-2eeb-4314-b812-7f9d1c9c47df',
				Logins: {
					[poolUrl]: result.getIdToken().getJwtToken()
				}
			})
      console.log(AWSConfig.credentials)

      // Make the call to obtain credentials
      AWSConfig.credentials.get(function(){

        // Credentials will be available when this function is called.
        var accessKeyId =  AWSConfig.credentials.accessKeyId;
        var secretAccessKey = AWSConfig.credentials.secretAccessKey;
        var sessionToken = AWSConfig.credentials.sessionToken;
        console.log(accessKeyId)
        })
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
  // parseCognitoWebResponse,
  signOutCognitoSession
}

export default cognitoId
