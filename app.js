require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const client = new MongoClient(process.env.MONGODB_URI);
let db;

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        dbName: process.env.MONGODB_DATABASE,
        crypto: { secret: process.env.MONGODB_SESSION_SECRET },
        ttl: 60 * 60
    }),
    saveUninitialized: false,
    resave: false
}));

app.listen(3000, async () => {
    await client.connect();
    db = client.db(process.env.MONGODB_DATABASE);
    console.log("App running at http://localhost:3000");
});

// ROUTES

app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/members');
    } else {
        res.sendFile(__dirname + '/public/home.html');
    }
});

app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/public/signup.html');
});

app.post('/signup', async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const { error } = schema.validate(req.body);
    if (error) return res.send("Invalid input. <a href='/signup'>Try again</a>");

    const hashed = await bcrypt.hash(req.body.password, 12);
    await db.collection('users').insertOne({
        name: req.body.name,
        email: req.body.email,
        password: hashed
    });

    req.session.user = { name: req.body.name, email: req.body.email };
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/login.html');
});

app.post('/login', async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const { error } = schema.validate(req.body);
    if (error) return res.send("Invalid login. <a href='/login'>Try again</a>");

    const user = await db.collection('users').findOne({ email: req.body.email });
    if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
        return res.send("Incorrect email or password. <a href='/login'>Try again</a>");
    }

    req.session.user = { name: user.name, email: user.email };
    res.redirect('/members');
});

app.get('/members', (req, res) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
  
    const images = ['img1.jpg', 'img2.jpg', 'img3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
  
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Members</title>
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body>
          <h1>Hello, ${req.session.user.name}.</h1>
          <img src="/images/${randomImage}" style="width:300px" /><br><br>
          <form method="GET" action="/logout">
            <button>Sign out</button>
          </form>
        </body>
        </html>
      `);      
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// 404 Handler
app.use((req, res) => {
    res.status(404).sendFile(__dirname + '/public/404.html');
});
