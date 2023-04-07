const mongoose = require('mongoose');

const typeSchema = new mongoose.Schema({
    english: String,
    chinese: String,
    japanese: String
});

const Type = mongoose.model('types', typeSchema);

module.exports = Type;