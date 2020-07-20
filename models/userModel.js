const mongoose = require("mongoose");
const Joi = require("joi");
const config = require("config");
const jwt = require("jsonwebtoken");

const Schema = mongoose.Schema;

const userSchema = new Schema({
  name: {
    type: String,
    //required: true,
    minlength: 2,
    maxlength: 255
  },

  username: {
    type: String,
    //required: true,
    unique: true
  },

  // gender: { type: String },

  phone: {
    type: String,
    validate: {
      validator: function (v) {
        return /\d{3}-\d{3}-\d{4}/.test(v);
      },
      message: props => `${props.value} is not a valid phone number!`
    },
    required: [true, "User phone number required"]
  },

  email: {
    type: String,
    //required: true,
    unique: true,
    minlength: 3
  },

  password: {
    type: String,
    //required: true,
    minlength: 8,
    maxlength: 255
  },

  profilePic: {
    type: String
  },

  reg_date: {
    type: Date,
    default: Date.now
  },

});

//custom method to generate authToken
userSchema.methods.generateAuthToken = function () {
  const token = jwt.sign(
    {
      _id: this._id,
      isAdmin: this.isAdmin
    },
    config.get("jwtPrivateKey"),
    { expiresIn: "7d" }
  );
  return token;
};

const User = mongoose.model("user", userSchema);

//function to validate user
function validateUser(user) {
  const schema = {
    // isAdmin: Joi.Boolean,
    // isBlocked: Joi.Boolean,
    name: Joi.string()
      .min(2)
      .max(50)
      .required(),
    username: Joi.string()
      .min(1)
      .max(50)
      .required(),

    phone: Joi.string(),
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

module.exports.userSchema = userSchema;

module.exports.User = User;

module.exports.validate = validateUser;
