var router = require("express").Router();
var config = require("../config/config.json");
const Users = require("../Model/Users");
var jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
var { check, validationResult } = require("express-validator");
const { ObjectId } = require("bson");
var nodemailer = require("nodemailer");
const UsersCodeLogin = require("../Model/UsersCodeLogin");
const UsersGitHubLogin = require("../Model/UsersGitHubLogin");
const err = require("../config/error_constants");
const warn = require("../config/info_constants");
var axios = require("axios");

/* * * * * * * * * * SIGN UP , FIRST TIME USER REGISTRATION * * * * * * * * * * */
router.post(
  "/signup",
  [
    check("name", warn.WARN_NAME_INPUT).not().isEmpty(),
    check("email", warn.WARN_EMAIL_INPUT).isEmail(),
    check("password", warn.WARN_PWD_INPUT).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
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

        const newUser = await user.save();
        const authtoken = generateJwtToken(newUser);
        req.session.jwt = authtoken;
        console.log("jwt", req.session.jwt);
        // SEND VERIFICATION MAIL //
        var url = config.baseUrl + "/verify/" + authtoken; // Define a URL Link Address for the user to click on to

        const emailText =
          "Click on the link below to verify your account \n" + url;

        const emailInfo = { user, emailText };
        sendEmail(emailInfo); // SEND EMAIL

        newUser.authtoken = authtoken;
        await newUser.save();
        res.status(200).send({
          status: "Verification Email has been sent successfully",
          message: "Please verify your email to complete registration",
        });
      }
    } catch (error) {
      res.status(500).send(err.ERR_SERVER);
    }
  }
);

/* * * * * * * * * * EMAIL VERIFICATION, USER SIGN UP * * * * * * * * * * */
router.get("/verify/:token", async (req, res) => {
  // GET THE TOKEN FROM DB AND VERIFY
  console.log("Token " + req.params.token);
  console.log("JWT token " + req.session.jwt);
  try {
    const decoded = jwt.verify(req.params.token, config.jwtSecret);
    const user = await Users.findById(decoded.user.id);
    if (user) {
      if (user.authtoken === req.params.token) {
        if (user.isVerified === true) {
          res.status(401).send(err.ERR_EMAIL_VERIFY);
        } else {
          user.isVerified = true;
          await user.save();
          const userCodeLogin = new UsersCodeLogin({ email: user.email });
          await userCodeLogin.save(); // Save in for users to login via OTP
          res.status(200).send({
            status: "Email verified, Registration Successful",
            message: "Welcome" + user.name,
          });
        }
      } else {
        res.status(402).send({
          status: err.ERR_INVALID_TOKEN,
          message: "Please try again!",
        });
      }
    }
  } catch (error) {
    res.status(500).send(err.ERR_SERVER);
  }
});

/* * * * * * * * * * * * LOGIN , EXISTING USER LOGIN WITH PASSWORD * * * * * * * * * * * */
router.post(
  "/login",
  [
    check("email", warn.WARN_EMAIL_INPUT).isEmail(),
    check("password", warn.WARN_PWD_REQ).exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    try {
      //Find if user already exists
      const user = await Users.findOne({ email });
      if (user) {
        const isMatch = await bcrypt.compare(password, user.password);
        if (user.isVerified === false) {
          // user has signed up , but not verified his email id
          res.status(400).send({
            status: err.ERR_EMAIL_NOT_VERIFY,
            message: "Please verify your email before loggin in",
          });
        }
        if (!isMatch) {
          res.status(400).send(err.ERR_PWD);
        }
      } else {
        res.status(400).send(err.ERR_USR_NOT_EXIST);
      }
      const authtoken = generateJwtToken(user);

      user.authtoken = authtoken;
      await user.save();

      req.session.jwt = authtoken;
      console.log("req", req.session.jwt);

      //return jsonweb token
      res.status(200).send({
        status: "Authentication successful",
        message: "Welcome " + user.name + " !",
      });
    } catch (error) {
      res.status(500).send(err.ERR_SERVER);
    }
  }
);

/* * * * * * * * * * * * LOGIN , USING GIT- HUB ACCOUNT * * * * * * * * * * * */
// https://github.com/login/oauth/authorize?client_id=d1e96ac29adf1b3544db&redirect_uri=http://localhost:3000/auth/oauthLogin /
router.get('/authorization',(req, res)=>{
    res.redirect('https://github.com/login/oauth/authorize?client_id=d1e96ac29adf1b3544db&redirect_uri=http://localhost:3000/auth/oauthLogin')
  })

router.get("/oauthLogin", (req, res) => {
  const requestToken = req.query.code;
  axios({
    // GET TOKEN FROM GITHUB
    method: "post",
    mode: "cors",
    url: `https://github.com/login/oauth/access_token?client_id=${config.clientID}&client_secret=${config.clientSecret}&code=${requestToken}`,
    headers: {
      accept: "application/json",
      "Access-Control-Allow-Origin": "*",
      crossorigin: true,
    },
  })
    .then((response) => {
      console.log("TOKEN RECEIVED => " + response.data.access_token);
      const accessToken = response.data.access_token;
      axios
        .get("https://api.github.com/user", {
          headers: {
            Authorization: "token " + accessToken,
          },
        })
        .then(async (response) => {
          const username = response.data.login;
          console.log("RESPONSE LOGIN ===>", response.data.login);

          // Find if the user exists already
          const gitUser = await UsersGitHubLogin.findOne({
            gitHubUserName: username,
          });
          if (gitUser) {
            gitUser.accessToken = accessToken;
            await gitUser.save();
            req.session.jwt = generateJwtToken(gitUser);
          } else {
            const newGitUser = new UsersGitHubLogin({
              gitHubUserName: response.data.login,
              accessToken: accessToken,
            });
            const newUser = await newGitUser.save();
            req.session.jwt = generateJwtToken(newUser);
          }
          res.redirect('http://localhost:3001/landPage')
          res
            .status(200)
            .send({ access_Token: accessToken, username: response.data.login });
        })
        .catch((err) => {
          console.log("error axios - 2nd Call", err);
        });
    })
    .catch((err) => {
      console.log("error axios- 1st Call", err);
    });
});

/* * * * * * * * * * * * LOGIN , EXISTING USER LOGIN WITH OTP/ACTIVATION CODE * * * * * * * * * * * */
router.post(
  "/loginwithotp",
  [check("email", warn.WARN_EMAIL_INPUT).isEmail()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { email } = req.body;
    try {
      //Find if user already exists
      const user = await UsersCodeLogin.findOne({ email });
      if (!user) {
        user = new UsersCodeLogin({
          email,
        });
      }
      user.otp = generateOtp(); // Generate OTP
      await user.save();
      const emailText = "Activation Code :" + user.otp;
      emailInfo = { user, emailText };
      sendEmail(emailInfo); // SEND CODE VIA EMAIL
      res.status(200).send({
        status: "Activation code sent via email",
        message: "Please enter the code to login",
      });
    } catch (error) {
      res.status(500).send(err.ERR_SERVER);
    }
  }
);

/* * * * * * * * * * * * LOGIN, VERIFY OTP CODE * * * * * * * * * * * */
router.post("/verifyotp", async (req, res) => {
  const otpuser = await UsersCodeLogin.findOne({ email: req.body.email });
//   const user = await Users.findOne({ email: req.body.email });
  if ((otpuser.otp == req.body.otp)) {
    otpuser.isOtpVerified = true;

    const authtoken = generateJwtToken(otpuser);

    // otpuser.authtoken = authtoken;

    // await user.save();
    await otpuser.save();

    req.session.jwt = authtoken;
    console.log("req", req.session.jwt);

    res.send("OTP successfully verified");
  } else {
    res.status(400).send(err.ERR_OTP_WRONG);
  }
});

/* * * * * * * * * * LOG OUT , USER LOG OUT * * * * * * * * * * */
router.get("/logout", async (req, res) => {
  //fetch the token
  const token = req.session.jwt;

  // check if it is token presernt
  if (!token) {
    return res.status(401).send(err.ERR_NO_TOKEN);
  }
  // verify token
  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    req.user = decoded.user;

    // CHECK IF LOGGED IN VIA GIT HUB
    const gitUser = await UsersGitHubLogin.findById(decoded.user.id);
    if (gitUser) {
      gitUser.accessToken = null;
      await gitUser.save();
    } else {
      const user = await Users.findById(decoded.user.id);
      user.authtoken = null;
      await user.save();
      await UsersCodeLogin.findOneAndUpdate(
        { email: user.email },
        { otp: null, isOtpVerified: false }
      );
    }
    req.session.jwt = null;

    res.status(200).send({
      status: "User Logged Out",
      message: "Logout Successful",
    });
  } catch (error) {
    res.status(402).send(err.ERR_INVALID_TOKEN);
  }
});

const generateOtp = () => {
  var otp = Math.random();
  otp = otp * 1000000;
  otp = parseInt(otp);
  return otp;
};

const generateJwtToken = (user) => {
  const payload = {
    user: {
      id: user.id,
    },
  };
  return jwt.sign(payload, config.jwtSecret);
};

const sendEmail = async (emailInfo) => {
  let transporter = nodemailer.createTransport({
    // name: "www.gmail.com", requireTLS: true, service: 'gmail'
    host: "smtp.gmail.com",
    port: 465, //587
    secure: true, // use SSL
    auth: {
      user: config.mailSenderEmailId, // username for your mail server
      pass: config.mailSenderPwd, // password
    },
  });

  // send mail with defined transport object
  let info = await transporter.sendMail(
    {
      to: emailInfo.user.email, // list of receivers seperated by comma
      subject: "Account Verification", // Subject line
      text: emailInfo.emailText, // plain text body
    },
    (error, info) => {
      if (error) {
        console.log(error);
        return;
      }
      console.log("Message sent successfully!");
      console.log(info);
      transporter.close();
    }
  );
};

module.exports = router;
