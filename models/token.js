const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true
    },
    valid: {
        type: Boolean,
        required: true
    }
});

const Token = mongoose.model('tokens', tokenSchema);

module.exports = Token;