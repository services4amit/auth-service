const mongoose = require('mongoose');
const schema = mongoose.Schema;

const UsersGitHubLoginSchema = new schema({
gitHubUserName: {
    type: String,
    required: true
},
accessToken: {
    type: String
}
});

module.exports = UsersGitHubLogin = mongoose.model('usersgithublogin', UsersGitHubLoginSchema);