var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');

// User Schema
var UserSchema = mongoose.Schema({
    username: {
        type: String,
        index: true
    },
    password: {
        type: String
    },
    email: {
        type: String
    },
    name: {
        type: String
    },
    facebook: {
        id: String,
        token: String,
        email: String,
        name: String
    },
    lastDateChange: {
        type: Number,
        default: 0
    },
    userWeight: {
        type: String,
        default: "..."
    },
    lastTimeDrinked: {
        type: String
    },
    lastDateDrinked: {
        type: Number,
        default: new Date().getDate()
    },
    drinkingCounter: {
        type: Number,
        default: 0
    },
    currentPeriod: {
        type: String
        /*type: Number,
        default: new Date().getDate()*/
    },
    currentPeriodDate: {
        type: String
    },
    joggingStart: {
        type: String,
        default: "..."
    },
    joggingStop: {
        type: String,
        default: "..."
    },
    cyclingStart: {
        type: String,
        default: "..."
    },
    cyclingStop: {
        type: String,
        default: "..."
    },
    strenghtenStart: {
        type: String,
        default: "..."
    },
    strenghtenStop: {
        type: String,
        default: "..."
    }
});

var User = module.exports = mongoose.model('User', UserSchema);

module.exports.createUser = function(newUser, callback) {
    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(newUser.password, salt, function(err, hash) {
            newUser.password = hash;
            newUser.save(callback);
        });
    });
}

module.exports.getUserByUsername = function(username, callback) {
    var query = { username: username };
    User.findOne(query, callback);
}

module.exports.getUserById = function(id, callback) {
    User.findById(id, callback);
}

module.exports.comparePassword = function(candidatePassword, hash, callback) {
    bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
        if (err) throw err;
        callback(null, isMatch);
    });
}
