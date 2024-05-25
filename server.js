const express = require("express")
const app = express()
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const db = require('./database');
app.use(bodyParser.json());

const SECRET_KEY = "your Secreate Key"

// post ApI User
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;

    db.run(query, [username, hashedPassword], function (err) {
        if (err) {
            return res.status(500).json({ message: 'User already exists.' });
        }
        res.status(201).json({ message: 'User created successfully.' });
    });
});

// Login API User 

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const query = `SELECT * FROM users WHERE username = ?`;

    db.get(query, [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '30D' });
        res.status(200).json({ token });
    });
});


// Middleware to verify token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
    
};

// Get user details API
app.get('/user', authenticateToken, (req, res) => {
    const query = `SELECT id, username FROM users WHERE id = ?`;

    db.get(query, [req.user.id], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.status(200).json(user);
    });
});

// Delete User API

app.delete('/user',authenticateToken ,(req,res)=>{

    const query = `DELETE FROM users WHERE id =?;`;

    db.get(query, [req.user.id],(req,user)=>{
        if(err || !user){
            return res.status(404).json({message:'user not found.'});
        }
        res.status(200).json(user);
    })
})


// Example of a protected route

app.get('/protected', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'This is a protected route.', user: req.user });
});



app.listen(3000,()=>{
    console.log(`Server Running At http:localhost:3000`)
})