const app = require('./controllers/server');
const { connectDB } = require('./helpers/connectDB');
const { asyncWrapper } = require('./helpers/asyncWrapper');
const dotenv = require('dotenv');
dotenv.config();


const start = asyncWrapper( async () => {
    await connectDB({ "refreshPoke": false });

    app.listen(process.env.AUTH_SERVER_PORT, async () => {
        console.log(`Server started on port ${process.env.AUTH_SERVER_PORT}`);
    });
})

start();
