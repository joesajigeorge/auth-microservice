const middy = require('@middy/core');
const createError = require('http-errors');
const errorHandler = require('../middlewares/error');
const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
const { poolData, pool_region } = require('../config/cognito-config');
const request = require('request');

const auth = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;
  const authorizationHeader = event.headers && event.headers.Authorization;

  // Authorization is empty
  if (!authorizationHeader) {
    throw createError.Unauthorized();
  }
  const decodedJwt = jwt.decode(authorizationHeader, {complete: true});
  console.log(decodedJwt);
  if (!decodedJwt) {
      throw createError.Unauthorized();
  }
  if (decodedJwt.payload.iss !== 'https://cognito-idp.'+pool_region+'.amazonaws.com/'+poolData.UserPoolId) {
      throw createError.Unauthorized();
  }
  if (!(decodedJwt.payload.token_use === 'id')) {
      throw createError.Unauthorized();
  }
  if (decodedJwt.payload.aud !== poolData.ClientId) {
      throw createError.Unauthorized();
  }
  request({url: 'https://cognito-idp.us-east-1.amazonaws.com/'+poolData.UserPoolId+'/.well-known/jwks.json', json: true}, (error, response, body) => {
      if (!error && response.statusCode === 200) {
          //console.log(body);
          pems = {};
          var keys = body['keys'];
          for(var i = 0; i < keys.length; i++) {
              var key_id = keys[i].kid;
              var modulus = keys[i].n;
              var exponent = keys[i].e;
              var key_type = keys[i].kty;
              var jwk = { kty: key_type, n: modulus, e: exponent};
              var pem = jwkToPem(jwk);
              pems[key_id] = pem;
          }
          var kid = decodedJwt.header.kid;
          var pem = pems[kid];
          if (!pem) {
              //context.fail("Unauthorized");
              throw createError.Unauthorized();
          }
          jwt.verify(authorizationHeader, pem, (err, decoded) => {
              if (err) {
                  throw createError.Unauthorized();
              }  
              console.log("Verified")
              return {
                statusCode: 200,
                body: JSON.stringify({ valid: true }),
              };
          });
      } else {
          throw createError.Unauthorized();
      }
  });
};

const handler = middy(auth)
  .use(errorHandler());

module.exports = { handler };
