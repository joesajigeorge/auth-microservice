const middy = require('@middy/core');
const jsonBodyParser = require('@middy/http-json-body-parser');
const validator = require('@middy/validator');
const errorHandler = require('../middlewares/error');

const db = require('../database/mongo');
const User = require('../models/user');
const signUpSchema = require('../schemas/signup.schema');
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const { poolData } = require('../config/cognito-config');

const signUp = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  const { email, password } = event.body;

  await db();

  const user = new User({
    email,
    password
  });

  await user.save();

  var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
  var attributeList = [];
  attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"email",Value:email}));

  userPool.signUp(email, password, attributeList, null, (err, result) => {
      if (err) {
        console.log("error")
        console.log(err)
          return;
      }
      const cognitoUser = result.user;
      console.log('user name is ' + cognitoUser.getUsername());
      return {
        statusCode: 200,
        body: JSON.stringify({ "status": 1, "message": "user: "+cognitoUser.getUsername() +" successfully added" }),
      };
  });
};

// Attach middy and returns handler
const handler = middy(signUp)
  .use(jsonBodyParser())
  .use(validator({ inputSchema: signUpSchema }))
  .use(errorHandler());

module.exports = { handler };
