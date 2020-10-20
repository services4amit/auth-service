var router = require("express").Router();
const authController = require("../controllers/authController");

//Sign up
router.post("/signup", authController.newSignUp);

//Login
router.post("/login", authController.login);

//Update Password
router.post("/updatePassword", authController.updatePassword);

//Logout
router.post("/logout", authController.logout);

//Home Page
router.post("/home", authController.homePage);

module.exports = router;
