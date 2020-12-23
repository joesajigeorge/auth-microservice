const middy = require('@middy/core');
const jsonBodyParser = require('@middy/http-json-body-parser');
const validator = require('@middy/validator');


const createError = require('http-errors');
const errorHandler = require('../middlewares/error');

const db = require('../database/mongo');
const User = require('../models/user');
const signInSchema = require('../schemas/signin.schema');

const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const { poolData } = require('../config/cognito-config');

// Business logic for sign in
const signIn = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  const { email, password } = event.body;

  // await db();

  // // Check if email exists
  // const user = await User.findOne({ email });

  // if (!user) {
  //   throw createError.Unauthorized();
  // }

  var authenticationData = {
    Username: email,
    Password: password,
  };
  var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(
      authenticationData
  );
  var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
  var userData = {
      Username: email,
      Pool: userPool,
  };
  var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
  cognitoUser.authenticateUser(authenticationDetails, {
      onSuccess: (result) => {
          console.log('access token : ' + result.getAccessToken().getJwtToken());
          console.log('id token : ' + result.getIdToken().getJwtToken());
          console.log('refresh token : ' + result.getRefreshToken().getToken());
          console.log('Successfully logged!');
          return {
            statusCode: 200,
            body: JSON.stringify({ "status": 1, "message": "user signed in successfully ", "data": result.getIdToken().getJwtToken()}),
          };
      },
      onFailure: (err) => {
        throw createError.Unauthorized();
      },
  });
};

// Attach middy and returns handler
const handler = middy(signIn)
  .use(jsonBodyParser())
  .use(errorHandler());

module.exports = { handler };
