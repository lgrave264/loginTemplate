require('dotenv').config();
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const {authenticateToken} = require('./middleware/tokenAuthenticate')

app.use(express.json())

const serverData = [
    {
        username: 'James Baxter',
        secret: 'sad bat'
    },
    {
        username: 'FP',
        secret: 'Mad'
    },
    {
        username: 'BP',
        secret: 'smart'
    }
]

app.get('/posts',authenticateToken, (req, res) => {
    res.json(serverData.filter(post => post.username === req.user.name));
})

app.post('/login', (req, res) => {
    console.log(req.body)
    const username = req.body.username
    const user = {name:username}
    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
    res.json({accessToken:accessToken})
})



app.listen(5000,()=>{
    console.log('server listening on port 5000')
})