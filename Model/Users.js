const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
    },
    authtoken: {
        type: String,
    },
    isVerified: {
        type: Boolean,
        default : false
    }
});

module.exports = Users = mongoose.model('users', UserSchema);