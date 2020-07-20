const express = require("express");
const router = express.Router();
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const path = require('path');

const { User, validate } = require("../models/userModel");
const auth = require("../Middleware/auth");

router.get("/", function (req, res) {
  res.send(JSON.stringify("Hello from user controller"));
});

router.get("/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.status(200).send(user);
  } catch (err) {
    res.status(500).send("There was a problem finding the user.");
  }
});

router.get("/:id", auth, async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.params.id }).select("-password");
    res.status(200).send(user);
  } catch (err) {
    res.status(500).send("There was a problem finding the user.");
    //res.status(400).send(err.message);
  }
});

router.post("/register", async (req, res) => {
  // validate the request body first
  const { error } = validate(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  //find an existing user
  let user = await User.findOne({ email: req.body.email });
  if (user) return res.status(400).send("User already registered.");

  const hashPassword = bcrypt.hashSync(req.body.password, 8);
  try {
    let user = new User({
      name: req.body.name,
      username: req.body.username,
      gender: req.body.gender,
      phone: req.body.phone,
      email: req.body.email,
      password: hashPassword,
      reg_date: req.body.reg_date
    });
    user = await user
      .save();

    //create a token
    const token = user.generateAuthToken();

    res.status(200).send({ auth: true, token: token });
  } catch (error) {
    console.log(error.message);
    res.status(500).send("There was problem registering the user.");
  }
});

router.post("/login", async (req, res) => {
  const { error } = validateLogin(req.body);
  if (error) return res.status(400).send("Invalid Email or Password");

  await User.findOne({ email: req.body.email }, (err, user) => {
    if (err) return res.status(500).send("Error on the server.");
    if (!user) return res.status(404).send("No user found.");
    if (user.isBlocked == true)
      return res.status(400).send("Your Account is suspended");

    const passValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passValid) return res.status(401).send({ auth: false, token: null });

    //generate json web token
    const token = user.generateAuthToken();
    const resBody = { authtoken: `${token}` };
    res.send(resBody);
  });
});

router.get("/logout", function (req, res) {
  res.status(200).send({ auth: false, token: null });
});

// UPDATES A SINGLE USER IN THE DATABASE
// Added auth middleware to make sure only an authenticated user can put to this route
router.put("/:id", auth, async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, req.body, { new: true }, function (
    err,
    user
  ) {
    if (err)
      return res.status(500).send("There was a problem updating the user.");
    res.status(200).send(user);
  });
});

router.delete("/:id", async (req, res) => {
  await User.findByIdAndRemove(req.params.id, function (err, user) {
    if (err)
      return res.status(500).send("There was a problem deleting the user.");
    res.status(200).send("User: " + user.name + " was deleted.");
  });
});

function validateLogin(user) {
  const schema = {
    email: Joi.string()
      .min(3)
      .max(255)
      .required()
      .email(),
    password: Joi.string()
      .min(8)
      .max(255)
      .required()
  };

  return Joi.validate(user, schema);
}

module.exports = router;
