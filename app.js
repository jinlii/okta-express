const express = require('express');
const OktaJwtVerifier = require('@okta/jwt-verifier');
var cors = require('cors');
const app = express();


const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: 'https://dev-368187.oktapreview.com/oauth2/default',
  assertClaims: {
    aud: 'api://default',
  },
});

/**
 * A simple middleware that asserts valid access tokens and sends 401 responses
 * if the token is not present or fails validation.  If the token is valid its
 * contents are attached to req.jwt
 */
function authenticationRequired(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/Bearer (.+)/);


  if (!match) {
    console.log('NO token!!');
    return res.status(401).end();
  }

  const accessToken = match[1];

  console.log('accessToken: ', accessToken);
  return oktaJwtVerifier.verifyAccessToken(accessToken)
    .then((jwt) => {
      req.jwt = jwt;
      next();
    })
    .catch((err) => {
      console.log('error token!!');
      res.status(401).send(err.message);
    });
}

/**
 * For local testing only!  Enables CORS for all domains
 */
app.use(cors());

app.get('/', (req, res) => res.send('Hello World!'))
/**
 * An example route that requires a valid access token for authentication, it
 * will echo the contents of the access token if the middleware successfully
 * validated the token.
 */
app.get('/secure', authenticationRequired, (req, res) => {
  res.json(req.jwt);
});

/**
 * Another example route that requires a valid access token for authentication, and
 * print some messages for the user if they are authenticated
 */
app.get('/api/messages', authenticationRequired, (req, res) => {
  console.log('req: ', req);
  res.json([{
    message: 'Hello, word!'
  }]);
});

app.listen(3000, () => console.log('Example app listening on port 3000!'))
