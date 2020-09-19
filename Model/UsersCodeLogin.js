const mongoose = require('mongoose');
const schema = mongoose.Schema;

const UsersCodeLoginSchema = new schema({
email: {
    type: String,
    required: true
},
otp: {
    type: Number
},
isOtpVerified: {
    type: Boolean,
    default: false
}
});

module.exports = UsersCodeLogin = mongoose.model('userscodelogin', UsersCodeLoginSchema);