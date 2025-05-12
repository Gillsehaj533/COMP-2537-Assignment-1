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

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('views'));

// Session config
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    dbName: process.env.MONGODB_DATABASE,
    crypto: { secret: process.env.MONGODB_SESSION_SECRET },
    ttl: 60 * 60 // 1 hour
  }),
  saveUninitialized: false,
  resave: false
}));

// Start server and DB
app.listen(3000, async () => {
  await client.connect();
  db = client.db(process.env.MONGODB_DATABASE);
  console.log("App running at http://localhost:3000");
});


// Home
app.get('/', (req, res) => {
  if (req.session.user) {
    res.redirect('/members');
  } else {
    res.sendFile(__dirname + '/views/home.ejs');
  }
});

// Signup Page
app.get('/signup', (req, res) => {
  res.sendFile(__dirname + '/views/signup.ejs');
});

// Signup Handler
app.post('/signup', async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(30).required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Invalid Signup</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h1>Invalid input!</h1>
        <p>Your signup information didn't pass validation.</p>
        <button onclick="location.href='/signup'">Try Again</button>
      </body>
      </html>
    `);
  }

  const hashed = await bcrypt.hash(req.body.password, 12);

  await db.collection('users').insertOne({
    name: req.body.name,
    email: req.body.email,
    password: hashed
  });

  req.session.user = { name: req.body.name, email: req.body.email };
  res.redirect('/members');
});

// Login Page
app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/views/login.ejs');
});

// Login Handler
app.post('/login', async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Invalid Login</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h1>Invalid login!</h1>
        <p>Please enter a valid email and password.</p>
        <button onclick="location.href='/login'">Try Again</button>
      </body>
      </html>
    `);
  }

  const user = await db.collection('users').findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Login Failed</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h1>Login failed!</h1>
        <p>Incorrect email or password.</p>
        <button onclick="location.href='/login'">Try Again</button>
      </body>
      </html>
    `);
  }

  req.session.user = { name: user.name, email: user.email };
  res.redirect('/members');
});

// Members Page (Protected)
app.get('/members', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const images = ['img1.jpg', 'img2.jpg', 'img3.jpg'];

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Members</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h1>Hello, ${req.session.user.name}.</h1>
      <img src="/images/${images}" style="width:300px"><br><br>
      <form method="GET" action="/logout">
        <button>Sign out</button>
      </form>
    </body>
    </html>
  `);
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 404 Not Found
app.use((req, res) => {
  res.status(404).sendFile(__dirname + '/views/404.ejs');
});
