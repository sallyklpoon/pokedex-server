const mongoose = require('mongoose');

const pokeUserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minLength: 3,
    maxLength: 20
  },
  password: {
    type: String,
    required: true,
    trim: true,
    minLength: 6,
    maxLength: 1000
  },
  date: {
    type: Date,
    default: Date.now
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minLength: 3
  },
  role: {
    type: String,
    required: true,
    trim: true,
    default: "user",
    enum: ["user", "admin"]
  }
});

const PokeUser =  mongoose.model('pokeusers', pokeUserSchema);

module.exports = PokeUser; //pokeUser is the name of the collection in the db
