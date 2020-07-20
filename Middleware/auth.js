//Configure JWT
const jwt = require("jsonwebtoken"); // used to create, sign, and verify tokens
const config = require('config'); // get config file

module.exports = function (req, res, next) {
  //get the token from the header if present
  const token = req.headers["x-access-token"] || req.headers["authorization"];
  console.log(token)
  //if no token found, return response (without going to the next middelware)
  if (!token)
    return res.status(401).send({ auth: false, message: "No token provided." });

  //verfiy token and return decoded data
  try {
    const decoded = jwt.verify(token, config.get("jwtPrivateKey"));
    req.user = decoded;
    next();
  } catch (err) {
    res.status(404).send("No user found.");
  }
};
