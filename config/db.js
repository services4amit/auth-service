const mongoose = require('mongoose');
const config = require('./config.json');
const db = config.mongoURI;

const connectDB = async () => {
    try {
        await mongoose.connect(db, {
            useNewUrlParser: true,
            useCreateIndex: true,
            useFindAndModify: false,
            useUnifiedTopology: true
        });
        mongoose.connection.on('connected', () => {
            console.log('MongoDB connected');
        });

        mongoose.connection.on('disconnected', () => {
            connectDB();
            console.log('MongoDB connection lost');
        });

        mongoose.connection.on('reconnect', () => {
            console.log('MongoDB reconnected');
        });
    } catch (error) {
        console.error(error.message);
        process.exit(1);
    }
}

module.exports = connectDB;