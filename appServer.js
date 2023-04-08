const app = require('./controllers/server');
const { connectDB } = require('./helpers/connectDB');
const { asyncWrapper } = require('./helpers/asyncWrapper');
const PORT = process.env.PORT || 6001;
const dotenv = require('dotenv');
dotenv.config();


const start = asyncWrapper( async () => {
    await connectDB({ "refreshPoke": false });

    app.listen(PORT, async () => {
        console.log(`Server started on port ${PORT}`);
    });
})

start();
