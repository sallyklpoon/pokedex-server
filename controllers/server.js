const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { asyncWrapper } = require('../helpers/asyncWrapper.js');
const User = require('../models/user');
const Token = require('../models/token');
const Pokemon = require('../models/pokemon');
const Request = require('../models/request.js');
const { parseAccessToken } = require('../helpers/parseTokens');

const dotenv = require('dotenv');
dotenv.config();

const REFRESH_TOKEN_HEADER = 'auth-token-refresh';
const ACCESS_TOKEN_HEADER = 'auth-token-access';
const ACCESS_EXPIRY = '20s';

const {
    PokemonAuthError,
    PokemonDbError
} = require("../helpers/errors.js");

const app = express();
app.use(express.json());
app.use(cors({
    exposedHeaders: [REFRESH_TOKEN_HEADER, ACCESS_TOKEN_HEADER],
}));

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Headers', '*');
    next();
  });

const hashedPassword = async password => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};

const authUser = async accessToken => {
    if (!accessToken) {
        throw new PokemonAuthError("No Token: Please provide the access token using the headers.");
    }
    try {
        jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
            if (err) {
                console.log(err);
            } else {
                console.log('User has access. :)');
            }
        })
    } catch (err) {
        throw new PokemonAuthError("Invalid Token Verification. Log in again.");
    }
};

const authAdmin = async accessToken => {
    const payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    console.log(payload);
    if (payload?.user?.role == "admin") {
        return next();
    }
    throw new PokemonAuthError("Access denied");
};

app.post('/register', asyncWrapper(async (req, res) => {
    const { username, password, email, role } = req.body;
    const hashPword = await hashedPassword(password);
    const newUser = { ...req.body, password: hashPword };

    try {
        const user = await User.create(newUser);
        res.send(user);
    } catch (err) {
        if (err.code == 11000) {
            throw new PokemonDbError('Email or Username is already in use. Please try again.');
        } else {
            throw new PokemonDbError('Data invalidity issue, please contact support admin.');
        }
    }
}));

app.post('/login', asyncWrapper(async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) res.status(401).json('Login Failure');

    const user = await User.findOne({ username });

    if (!user) throw new PokemonAuthError("User not found");

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) res.status(401).json('Login Failure');

    const accessToken = jwt.sign({ user: user }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20s' });
    const refreshToken = jwt.sign({ user: user }, process.env.REFRESH_TOKEN_SECRET);

    Token.create({ token: refreshToken, valid: true });

    res.header(ACCESS_TOKEN_HEADER, accessToken);
    res.header(REFRESH_TOKEN_HEADER, refreshToken);
    res.send(user);
}));

app.get('/logout', asyncWrapper(async (req, res) => {
    try {
        const refreshToken = req.headers[REFRESH_TOKEN_HEADER];

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

app.get('/requestNewAccessToken', asyncWrapper(async (req, res) => {
    const refreshToken = req.headers[REFRESH_TOKEN_HEADER];

    if (!refreshToken) {
        throw new PokemonAuthError("No token: Please provide a token.");
    }
    if (!refreshToken) {
        throw new PokemonAuthError("Invalid Token: Refresh token not found. Please provide a valid token.");
    }

    const foundToken = await Token.findOne({ token: refreshToken });
    if (!foundToken) {
        throw new PokemonAuthError("Invalid Token: Token not found. Please provide a valid token.");
    }
    try {
        const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const newAccessToken = jwt.sign({ user: payload.uesr }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20s' });
        res.header(ACCESS_TOKEN_HEADER, newAccessToken);
        res.send("New access token, sent!");
    } catch (e) {
        throw new PokemonAuthError("Invalid Token: Please provide a valid token.");
    };
}));


/**
 * Get all pokemons based on filters of count and after.
 */
app.get('/pokemons', async (req, res) => {
    let accessToken = req.headers['auth-token-access'];
    await authUser(accessToken);

    try {
        const pokemonUrl = 'https://raw.githubusercontent.com/fanzeyi/pokemon.json/master/pokedex.json';
        const pokemonRes = await fetch(pokemonUrl);
        let pokemonData = await pokemonRes.json();
        res.status(200).json(pokemonData);
    } catch (err) {
        throw new PokemonDbError('Error retreiving pokemons. Please try again.')
    }
});

/**
 * Get a Pokemon based on id.
 */
app.get('/pokemon/:id', async (req, res) => {
    try {
        // proof of concept! IRL, it's more efficient to pull from all Pokemons data stored in local storage.
        return res.status(200).json('Pika pika!');
    } catch (err) {
        return res.status(400).json({ errMsg: 'Error fetching pokemon.' });
    }
});

app.get('/pokemonTypes', async (req, res) => {
    authUser(req.headers['auth-token-access'])
    try {
        const typesUrl = 'https://raw.githubusercontent.com/fanzeyi/pokemon.json/master/types.json';
        const typesRes = await fetch(typesUrl);
        let typesData = await typesRes.json();
        res.status(200).json(typesData);
    } catch (err) {
        throw new PokemonDbError('Error retrieving types. Please try again.')
    }
});

app.post('/request/create', async (req, res) => {
    const requestData = req.body;

    try {
        const reqRes = await Request.create(requestData);
        res.status(200).send(reqRes);
    } catch (err) {
        res.status(501).send('Pokemon DB error: error tracking endpoint request.')
    }
})


app.use((_req, res) => {
    res.status(404).json({
        msg: "Improper route."
    });
});

module.exports = app;

