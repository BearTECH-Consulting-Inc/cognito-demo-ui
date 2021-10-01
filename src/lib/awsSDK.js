import {
    config as AWSConfig,
    CognitoIdentityCredentials as _cic,
    Lambda as _lambda
  } from 'aws-sdk'
  
  const AWSRegion = "us-east-2"
  
  AWSConfig.region = AWSRegion
  
  export { AWSRegion, AWSConfig, _cic, _lambda }