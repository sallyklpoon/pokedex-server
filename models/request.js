const mongoose = require('mongoose');

const requestSchema = new mongoose.Schema({
    username: {
        type: String,
        default: 'unauthorized'
    },
    endpoint: {
        type: String,
        required: true
    },
    accessedAt: {
        type: Date,
        default: Date.now()
    },
    status: {
        type: Number,
        required: true
    }
});

const Request = mongoose.model('requests', requestSchema);

module.exports = Request;
