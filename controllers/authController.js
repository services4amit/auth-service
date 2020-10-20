const bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");

const Users = require("../Model/Users");
const err = require("../config/error_constants");
var config = require("../config/config.json");

/**
 * when a new user sign's up for the first
 */
exports.newSignUp = async (req, res, next) => {
  const { name, email, password } = req.body;
  try {
    let user = await Users.findOne({ email });
    if (user) {
      res.status(200).send(err.ERR_USR_EXIST);
    } else {
      user = new Users({
        name,
        email,
        password,
      });

      // Encrypt pwd using bcrypt
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password.toString(), salt);
      user.isVerified = true;
      const newUser = await user.save();

      // Generate authentication token
      const authtoken = generateJwtToken(newUser);
      req.session.jwt = authtoken;

      // SEND VERIFICATION MAIL //

      newUser.authtoken = authtoken;
      await newUser.save();
      res.status(201).json({
        status: "Success",
        data: {
          user: newUser,
        },
      });
    }
  } catch (error) {
    res
      .status(400)
      .send(
        `Something went wrong and could not create new user, error is ${error}`
      );
  }
};

/**
 * when an existing user log's in
 */
exports.login = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    //Find if user already exists
    const user = await Users.findOne({ email });
    if (user) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        res.status(401).send({
          status: "Failure",
          message: "Invalid Password - Unauthorized error",
        });
      } else {
        const authtoken = generateJwtToken(user);

        user.authtoken = authtoken;
        await user.save();

        req.session.jwt = authtoken;

        res.status(200).send({
          status: "Authentication successful",
          message: "Welcome " + user.name + "!",
          authtoken: authtoken,
        });
      }
    } else {
      res.status(401).send({
        status: "Failure",
        message: "User does not exist",
      });
    }
  } catch (error) {
    res.status(400).send({
      status: "Success",
      message: `Login Failed with an internal error, error is ${error}`,
    });
  }
};

/**
 * If the user wants to update his/her password when logged in
 */
exports.updatePassword = async (req, res, next) => {
  const { authtoken, oldPassword, newPassword } = req.body;
  try {
    const decoded = jwt.verify(authtoken, config.jwtSecret);
    const user = await Users.findById(decoded.user.id);
    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (user.authtoken === "" || !user) {
      res.status(401).send({
        status: "Failure",
        message: "Unauthorized User, Please login to continue",
      });
    } else if (!isMatch) {
      res.status(401).send({
        status: "Failure",
        message: "Unauthorized User",
      });
    } else {
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword.toString(), salt);
      user.save();

      res.status(201).send({
        status: "Sucess",
        message: "password has been updated",
      });
    }
  } catch (error) {
    res.status(400).send({
      status: "Failure",
      message: "Update of password is failed due to an internal error",
    });
  }
};

/**
 * Logout Function
 */
exports.logout = async (req, res, next) => {
  //fetch the token
  const token = req.session.jwt;

  // check if it is token presernt

  // verify token
  try {
    const decoded = jwt.verify(req.body.authtoken, config.jwtSecret);
    // req.user = decoded.user;

    const user = await Users.findById(decoded.user.id);
    user.authtoken = "";
    await user.save();

    req.session.jwt = null;

    res.status(200).send({
      status: "User Logged Out",
      message: "Logout Successful",
      authtoken: null,
    });
  } catch (error) {
    res.status(402).send({
      status: "Failure",
      message: "Failed to log out",
    });
  }
};

/**
 * Fetching User Info for home page
 */
exports.homePage = async (req, res, next) => {
  try {
    let decoded = jwt.verify(req.body.authtoken, "uscc");

    res.status(200).send({ name: decoded.user.id });
  } catch (e) {
    res.status(500).send("NOT_LOGGED_IN");
  }
};

/**
 * Internal function to generate JWT token
 */
const generateJwtToken = (user) => {
  const payload = {
    user: {
      id: user.id,
    },
  };
  return jwt.sign(payload, config.jwtSecret);
};
