var express = require('express');
var app = express();
var bodyParser = require('body-parser');
const fileOwner = 'server.js';
var cors = require('cors');
var cookieSession = require('cookie-session');

const connectDB = require('./config/db');

//connect to DB 
connectDB();


app.set('trust proxy', true)
app.use(cookieSession({
    signed: false
}))
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// app.use(function (req, res, next) {
//    res.header('Access-Control-Allow-Origin', "*");
//    res.header('Access-Control-Allow-Methods', "POST,DELETE, PUT, GET,OPTIONS");
//    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With , Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization");
//    next();
// })

app.use('/auth', require('./Service/auth'));
app.use('/', function (req, res) {
    res.json({
        status: 'API Its Default',
        message: 'Welcome to Default!'
    });
})

var server = app.listen(8090, function () {
    //    var host = server.address().address;
    //    var port = server.address().port;
    console.log('App listening on port : 8090');
});





