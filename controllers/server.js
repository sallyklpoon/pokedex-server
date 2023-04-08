const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { asyncWrapper } = require('../helpers/asyncWrapper.js');
const User = require('../models/user');
const Token = require('../models/token');
const Request = require('../models/request.js');

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
    authUser(accessToken);

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
});

app.get('/adminReports/uniqueUsers', async (req, res) => {
    authUser(req.headers['auth-token-access']);
    if (!req.headers['user-role'] || !req.headers['user-role'] == 'admin') {
        res.status(403).send('Pokemon Auth Error: Forbidden Access.');
    };
    
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    try {
        const logs = await Request.aggregate([
            // // Match documents with a date greater than or equal to the start time
            { $match: { accessedAt: { $gte: oneDayAgo }, username: { $ne: 'unauthorized-user' } } },
            // Group documents by username and count the number of documents for each username
            { $group: { _id: '$username', count: { $sum: 1 } } }
        ]);
        const usernames = logs.map(item => item._id);
        res.status(200).send(usernames);
    } catch (err) {
        console.log(err);
        res.status(400).send('Error retreiving report :(');
    }
});

app.get('/adminReports/topUsers', async (req, res) => {
    authUser(req.headers['auth-token-access']);
    if (!req.headers['user-role'] || !req.headers['user-role'] == 'admin') {
        res.status(403).send('Pokemon Auth Error: Forbidden Access.');
    };

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    let topUsers = [];

    try {
        const logs = await Request.aggregate([
            { $match: { accessedAt: { $gte: oneDayAgo }, username: { $ne: 'unauthorized-user' } } },
            { $group: { _id: '$username', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);
        res.status(200).send(logs);
    } catch (err) {
        console.log(err);
        res.status(400).send('Error retreiving report :(');
    }

});

app.get('/adminReports/endpointTop', async (req, res) => {
    authUser(req.headers['auth-token-access']);
    if (!req.headers['user-role'] || !req.headers['user-role'] == 'admin') {
        res.status(403).send('Pokemon Auth Error: Forbidden Access.');
    };

    try {
        const logs = await Request.aggregate([
            // Group documents by endpoint and username, and count the number of documents for each username in each endpoint group
            { $group: { _id: { endpoint: '$endpoint', username: '$username' }, count: { $sum: 1 } } },
            // Group the result by endpoint and push each username/count pair into an array
            { $group: { _id: '$_id.endpoint', users: { $push: { username: '$_id.username', count: '$count' } } } },
        ]);

        const endpointTopUsers = logs.map(log => {
            return {
                "endpoint": log._id,
                "user": log.users.sort((a, b) => b.count - a.count)[0]
            }
        })

        res.status(200).send(endpointTopUsers);
    } catch (err) {
        console.log(err);
        res.status(400).send('Error retreiving report :(');
    }
});

app.get('/adminReports/endpoint4xxErrors', async (req, res) => {
    authUser(req.headers['auth-token-access']);
    if (!req.headers['user-role'] || !req.headers['user-role'] == 'admin') {
        res.status(403).send('Pokemon Auth Error: Forbidden Access.');
    };

    try {
        const logs = await Request.aggregate([
            { $match: { status: { $gte: 400, $lt: 500 } } },
            {
                $group: {
                    _id: {
                        endpoint: "$endpoint",
                        accessedAt: "$accessedAt",
                        status: "$status"
                    },
                    count: { $sum: 1 }
                }
            },
            {
                $sort: {
                    "_id.accessedAt": -1
                }
            }
        ]);
        res.status(200).send(logs);
    } catch (err) {
        console.log(err);
        res.status(400).send('Error retreiving report :(');
    }

});

app.get('/adminReports/recentErrors', async (req, res) => {
    authUser(req.headers['auth-token-access']);
    if (!req.headers['user-role'] || !req.headers['user-role'] == 'admin') {
        res.status(403).send('Pokemon Auth Error: Forbidden Access.');
    };

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    try {
        const logs = await Request.aggregate([
            { $match: { status: { $gte: 500, $lt: 600 }, accessedAt: { $gte: oneDayAgo } } },
            {
                $group: {
                    _id: {
                        endpoint: "$endpoint",
                        accessedAt: "$accessedAt",
                        status: "$status"
                    },
                    count: { $sum: 1 }
                }
            },
            {
                $sort: {
                    "_id.accessedAt": -1
                }
            }
        ]);
        res.status(200).send(logs);
    } catch (err) {
        console.log(err);
        res.status(400).send('Error retreiving report :(');
    }
});


app.use((_req, res) => {
    res.status(404).json({
        msg: "Improper route."
    });
});

module.exports = app;
