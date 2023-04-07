const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const Pokemon = require('../models/pokemon');

const connectDB = async input => {
    try {
        const x = await mongoose.connect(process.env.DB_STRING);
        console.log("MongoDB connection successful");
        if (input.refreshPoke == true) {
            refreshDatabase();
        }
    } catch (e) {
        console.log("Error connecting to DB.");
    }
};

const refreshDatabase = async () => {

    try {
        await mongoose.connection.db.dropCollection('pokemons');
    } catch (err) {
        console.log(`Collection does not exist ERR: ${err}\nCreating new collection.`);
    }

    const pokemonUrl = 'https://raw.githubusercontent.com/fanzeyi/pokemon.json/master/pokedex.json';
    const pokemonRes = await fetch(pokemonUrl);
    let pokemonData = await pokemonRes.json();

    // Correct the data for Speed Attack and Speed Defense
    pokemonData.map(pokemon => {
        pokemon['base']['Speed Attack'] = pokemon['base']['Sp. Attack'];
        pokemon['base']['Speed Defense'] = pokemon['base']['Sp. Defense'];
        delete pokemon['base']['Sp. Attack'];
        delete pokemon['base']['Sp. Defense'];       
    });

    const updateRes = Pokemon.insertMany(pokemonData);
    if (updateRes) {
        console.log("Pokemons updated!");
    }

    await Pokemon.createIndexes();
}

module.exports = { connectDB, refreshDatabase };
