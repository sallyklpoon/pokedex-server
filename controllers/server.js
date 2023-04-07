const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { asyncWrapper } = require('../helpers/asyncWrapper.js');
const User = require('../models/user');
const Token = require('../models/token');
const Pokemon = require('../models/pokemon');
const { parseAccessToken } = require('../helpers/parseTokens');
const { setAccessToken } = require('../helpers/cookie.js');

const dotenv = require('dotenv');
dotenv.config();

const REFRESH_TOKEN_HEADER = 'auth-token-refresh';
const ACCESS_TOKEN_HEADER = 'auth-token-access';
const ACCESS_EXPIRY = '20';

const {
    PokemonAuthError,
    PokemonDbError
} = require("../helpers/errors.js");

const app = express();
app.use(express.json());
app.use(cors({
    origin: '*',
    exposedHeaders: [REFRESH_TOKEN_HEADER, ACCESS_TOKEN_HEADER],
}));

const hashedPassword = async password => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};

const authUser = asyncWrapper(async (req, res, next) => {
    const token = req.header('authorization');
    if (!token) {
        throw new PokemonAuthError("No Token: Please provide the access token using the headers.");
    }

    const accessToken = await parseAccessToken(token);
    try {
        const verified = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET)
        next();
    } catch (err) {
        throw new PokemonAuthError("Invalid Token Verification. Log in again.");
    }
});

const authAdmin = asyncWrapper(async (req, res, next) => {
    const token = req.header('authorization');
    const accessToken = await parseAccessToken(token);

    const payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    console.log(payload);
    if (payload?.user?.role == "admin") {
        return next();
    }
    throw new PokemonAuthError("Access denied");
});

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

    res.header(ACCESS_TOKEN_HEADER, accessToken);
    res.header(REFRESH_TOKEN_HEADER, refreshToken);
    res.send(user);
}));

app.get('/logout', asyncWrapper(async (req, res) => {
    try {
        const refreshToken = req.headers[REFRESH_TOKEN_HEADER];
        console.log(refreshToken);

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
    const token = req.header.REFRESH_TOKEN_HEADER;

    if (!token) {
        throw new PokemonAuthError("No token: Please provide a token.");
    }
    const refreshToken = await parseRefreshToken(token);
    if (!refreshToken) {
        throw new PokemonAuthError("Invalid Token: Refresh token not found. Please provide a valid token.");
    }

    const foundToken = await Token.findOne({ token: refreshToken });
    if (!foundToken) {
        throw new PokemonAuthError("Invalid Token: Token not found. Please provide a valid token.");
    }
    try {
        const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const newAccessToken = jwt.sign({ user: payload.uesr }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_EXPIRY });
        res.header(ACCESS_TOKEN_HEADER, newAccessToken);
        res.send("All good!");
    } catch (e) {
        throw new PokemonAuthError("Invalid Token: Please provide a valid token.");
    };
}));


// app.use(authUser);
/**
 * Get all pokemons based on filters of count and after.
 */
app.get('/pokemons', async (req, res) => {
    try {
        const pokemonUrl = 'https://raw.githubusercontent.com/fanzeyi/pokemon.json/master/pokedex.json';
        const pokemonRes = await fetch(pokemonUrl);
        let pokemonData = await pokemonRes.json();
        res.status(200).json(pokemonData);
    } catch (err) {
        throw new PokemonDbError('Error retreiving pokemons. Please try again.')
    }
});

app.get('/pokemonTypes', async (req, res) => {
    try {
        const typesUrl = 'https://raw.githubusercontent.com/fanzeyi/pokemon.json/master/types.json';
        const typesRes = await fetch(typesUrl);
        let typesData = await typesRes.json();
        res.status(200).json(typesData);
    } catch (err) {
        throw new PokemonDbError('Error retrieving types. Please try again.')
    }
});


app.use((_req, res) => {
    res.status(404).json({
        msg: "Improper route."
    });
});

module.exports = app;

