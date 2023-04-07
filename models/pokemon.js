const mongoose = require('mongoose');
const nodecache = require('node-cache');
const appCache = new nodecache({ stdTTL : 3599 });

const validType = async (types) => {
    if (appCache.has("types") == false) {
        // if Types is not cached, we should cache types data dynamically
        const typeUrl = 'https://raw.githubusercontent.com/fanzeyi/pokemon.json/master/types.json';
        const typeRes = await fetch(typeUrl);
        let typeData = await typeRes.json();
        let data = []

        for (i = 0; i < typeData.length; i++) {
            data.push(typeData[i]['english']);
        }
        appCache.set("types", data);
    }
    let valid = true;

    // Validate types is in enumerators of types.
    types.forEach(type => {
        if (!appCache.get("types").includes(type)){
            valid = false;
        }
    })
    return valid && types.length <= 2;
}


const pokemonSchema = new mongoose.Schema({
    base: {
        HP: { type: Number, min: 1, required: true},
        Attack: { type: Number, min: 1, required: true },
        Defense: { type: Number, min: 1, required: true },
        Speed: { type: Number, min: 1, required: true },
        'Speed Attack': { type: Number, min: 1, required: true },
        'Speed Defense': { type: Number, min: 1, required: true },
    },
    id: { type: Number, required: true, index: true , unique: true },
    name: {
        english: { type: String, maxLength: 20, required: true },
        japanese: String,
        chinese: String,
        french: String
    },
    type: { type: [String], validate: (v) => {
        let valid = validType(v);
        if (!valid) {
            throw new Error(`Invalid types: ${v}. Value must be a valid pokemon type and array of length <= 2.`)
        }
        return valid;
    }, required: true},
    __v: Number
})


const Pokemon = mongoose.model('pokemons', pokemonSchema);

module.exports = Pokemon;
