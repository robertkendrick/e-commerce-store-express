const jwt = require("jsonwebtoken");
const { jwtSecret } = require("../../config");

module.exports = {
  check: (req, res, next) => {
    const authHeader = req.headers['authorization'];
    console.log('isAuthenticatedMiddleware-check():', authHeader);
    // IF no auth headers are provided
    // THEN return 401 Unauthorized error
    if (!authHeader) {
      return res.status(401).json({
        status: false,
        error: {
          message: 'Auth headers not provided in the request.'
        }
      });
    }

    // IF bearer auth header is not provided
    // THEN return 401 Unauthorized error
    if (!authHeader.startsWith('Bearer')) {
      return res.status(401).json({
        status: false,
        error: {
          message: 'Invalid auth mechanism.'
        }
      });
    }

    const token = authHeader.split(' ')[1];

    // IF bearer auth header is provided, but token is not provided
    // THEN return 401 Unauthorized error
    if (!token) {
      return res.status(401).json({
        status: false,
        error: {
          message: 'Bearer token missing in the authorization headers.'
        }
      })
    }

    // verify decodes the token to produce user (or err)
    jwt.verify(token, jwtSecret, (err, user) => {
      if (err) {
        return res.status(403).json({
          status: false,
          error: 'Invalid access token provided, please login again.'
        });
      }

      console.log('isAuthenticatedMiddleware-check()-user:', user);
      // Save the user object for further use
      // eg. This is how the app can know who the logged in user is
      req.user = user;
      next();
    });
  }
}
