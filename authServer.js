require('dotenv').config();
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const { authenticateToken } = require('./middleware/tokenAuthenticate');
const { generateAccessToken, generateRefreshToken } = require('./middleware/tokenGeneration');

//require('crypto').randomBytes(64).toString('hex')

app.use(express.json());

app.post('/login', (req, res) => {
    // Authorization USER
    console.log(req.body);
    const username = req.body.username;
    const user = { name: username };
    // Assuming that the authentication has been completed the JWT.sign should also included the password 
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokenDatabase.push(refreshToken);
    res.json({ accessToken, refreshToken });
});

app.delete('/logout', (req, res) => {
    refreshTokenDatabase = refreshTokenDatabase.filter(token => token !== req.body.token);
    res.sendStatus(204);
});

let refreshTokenDatabase = [];

app.post('/token', (req, res) => {
    const clientRefreshToken = req.body.token;
    if (clientRefreshToken == null)  return res.sendStatus(401);
    if (!refreshTokenDatabase.includes(clientRefreshToken)) return res.sendStatus(403);
    jwt.verify(clientRefreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403);
        const accessToken = generateAccessToken({name: user.name}); // normally 10-25 mins
        res.json({ accessToken });
    });
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
    console.log('listening on port ' + port);
});