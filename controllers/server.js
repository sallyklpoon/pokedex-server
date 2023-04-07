const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { asyncWrapper } = require('../helpers/asyncWrapper.js');
const User = require('../models/user');
const Token = require('../models/token');
const { parseRefreshToken } = require('../helpers/parseTokens.js');

const dotenv = require('dotenv');
dotenv.config();

const TOKEN_HEADER = 'Authorization';
const ACCESS_EXPIRY = '20s';

const {
    PokemonAuthError,
    PokemonDbError
} = require("../helpers/errors.js");

const app = express();
app.use(express.json());
app.use(cors({
    expoesdHeaders: [TOKEN_HEADER]
}));

const hashedPassword = async password => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};

app.post('/register', asyncWrapper(async (req, res) => {
    const { username, password, email, role } = req.body;
    const hashPword = await hashedPassword(password);
    const newUser = { ...req.body, password: hashPword };

    try {
        const user = await User.create(newUser);
        res.send(user);
    } catch (err) {
        console.log(err);
        if (err.code == 11000) {
            throw new PokemonDbError('Email or Username is already in use. Please try again.');
        } else {
            throw new PokemonDbError('Data invalidity issue, please contact support admin.');
        }
    }
}));

app.post('/login', asyncWrapper(async (req, res) => {

    const { username, password } = req.body;
    if (!username || !password) throw new PokemonAuthError("Incorrect Payload");

    const user = await User.findOne({ username });

    if (!user) throw new PokemonAuthError("User not found");

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) throw new PokemonAuthError("Password is incorrect");

    const accessToken = jwt.sign({ user: user }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_EXPIRY });
    const refreshToken = jwt.sign({ user: user }, process.env.REFRESH_TOKEN_SECRET);

    Token.create({ token: refreshToken, valid: true });

    res.header(TOKEN_HEADER, `BEARER ${accessToken} REFRESH ${refreshToken}`);
    res.send(user);
}));

app.get('/logout', asyncWrapper(async (req, res) => {
    try {
        const refreshToken = await parseRefreshToken(req.headers.authorization);

        let invalidateToken = await Token.findOneAndDelete({ token: refreshToken });
        if (invalidateToken) {
            setTimeout(() => {
                res.send("Log out successful.");
            }, ACCESS_EXPIRY); // timeout ensures that access token is also invalid
        } else {
            throw new PokemonAuthError("Error logging out user, invalid token.");
        };

    } catch (e) {
        throw new PokemonAuthError("Error logging out user, please try again.");
    }
}));

app.post('/requestNewAccessToken', asyncWrapper(async (req, res) => {
    const token = req.header(TOKEN_HEADER);

    if (!token) {
        throw new PokemonAuthError("No token: Please provide a token.");
    }
    const refreshToken = await parseRefreshToken(token);
    if (!refreshToken) {
        throw new PokemonAuthError("A: Invalid Token: Please provide a valid token.");
    }

    const foundToken = await Token.findOne({ token: refreshToken });
    if (!foundToken) {
        throw new PokemonAuthError("B: Invalid Token: Please provide a valid token.");
    }
    try {
        const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const newAccessToken = jwt.sign({ user: payload.uesr }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_EXPIRY });
        res.header(TOKEN_HEADER, `BEARER ${newAccessToken}`);
        res.send("All good!");
    } catch (e) {
        throw new PokemonAuthError("C: Invalid Token: Please provide a valid token.");
    };
}));

app.use((_req, res) => {
    res.status(404).json({
        msg: "Improper route. Check API docs plz."
    });
});

module.exports = app;

