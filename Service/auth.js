var router = require("express").Router();
var config = require("../config/config.json");
const Users = require("../Model/Users");
var jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
var { check, validationResult } = require("express-validator");
const { ObjectId } = require("bson");
var nodemailer = require("nodemailer");
const err = require("../config/error_constants");
const warn = require("../config/info_constants");
var axios = require("axios");

/* * * * * * * * * * SIGN UP , FIRST TIME USER REGISTRATION * * * * * * * * * * */
router.post(
  "/signup",
  async (req, res) => {

    console.log(req.body);
    const { name, email, password } = req.body;
    try {
      //Find if user already exists
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
        const authtoken = generateJwtToken(newUser);
        req.session.jwt = authtoken;
        console.log("jwt", req.session.jwt);
        // SEND VERIFICATION MAIL //

        newUser.authtoken = authtoken;
        await newUser.save();
        res.status(200).send({
          status: "SUCCESSFUL",
          message: "Sign Up successful",
          authtoken:authtoken
        });
      }
    } catch (error) {
      res.status(500).send(err.ERR_SERVER);
    }
  }
);



/* * * * * * * * * * * * LOGIN , EXISTING USER LOGIN WITH PASSWORD * * * * * * * * * * * */
router.post(
  "/login",
  async (req, res) => {
    const { email, password } = req.body;
    try {
      //Find if user already exists
      const user = await Users.findOne({ email });
      if (user) {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          res.status(400).send(err.ERR_PWD);
        } else {

          const authtoken = generateJwtToken(user);

          user.authtoken = authtoken;
          await user.save();

          req.session.jwt = authtoken;
          console.log("req", req.session.jwt);

          //return jsonweb token


          console.log("req", req.session.jwt);
          res.status(200).send({
            status: "Authentication successful",
            message: "Welcome " + user.name + " !",
            authtoken:authtoken
          });

        }


      } else {
        res.status(400).send(err.ERR_USR_NOT_EXIST);
      }

    } catch (error) {
      res.status(500).send(err.ERR_SERVER);
    }
  }
);





/* * * * * * * * * * LOG OUT , USER LOG OUT * * * * * * * * * * */
router.post("/logout", async (req, res) => {
  //fetch the token
  const token = req.session.jwt;
  console.log("token", token)

  // check if it is token presernt
 
  // verify token
  try {
    console.log("token in logot",req.body.authtoken)
    const decoded = jwt.verify(req.body.authtoken, config.jwtSecret);
    // req.user = decoded.user;

  
      const user = await Users.findById(decoded.user.id);
      user.authtoken = '';
      await user.save();
  
    
    req.session.jwt = null;

    res.status(200).send({
      status: "User Logged Out",
      message: "Logout Successful",
      authtoken:null
    });
  } catch (error) {
    res.status(402).send(err.ERR_INVALID_TOKEN);
  }
});



const generateJwtToken = (user) => {
  const payload = {
    user: {
      id: user.id,
    },
  };
  return jwt.sign(payload, config.jwtSecret);
};


router.post("/home", (req, res) => {

  try {
    console.log("cookie",req.body);

    let decoded = jwt.verify(req.body.authtoken, "uscc");
    console.log("decode", decoded);

    res.status(200).send({name:decoded.user.id})

  } catch (e) {
    console.log(e);
    res.status(500).send("NOT_LOGGED_IN")
  }


})


module.exports = router;
