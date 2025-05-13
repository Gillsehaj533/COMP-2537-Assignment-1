require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const { MongoClient } = require('mongodb');
const path = require('path');

const app = express();
const client = new MongoClient(process.env.MONGODB_URI);
let db;

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

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

app.get('/', (req, res) => {
  res.render('home', { user: req.session.user });
});


// Signup Page
app.get('/signup', (req, res) => {
  res.render('signup', { error: null, user: req.session.user });
});


// Signup Handler
app.post('/signup', async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(30).required()
  });

  
  const { error } = schema.validate(req.body);
  if (error) return res.render('signup', { error: error.details[0].message, user: req.session.user });
  const hashed = await bcrypt.hash(req.body.password, 12);

  const isFirstUser = (await db.collection('users').countDocuments()) === 0;

  await db.collection('users').insertOne({
    name: req.body.name,
    email: req.body.email,
    password: hashed,
    type: isFirstUser ? 'admin' : 'user'
  });
  

  req.session.user = { name: req.body.name, email: req.body.email };
  res.redirect('/members');
});

// Login Page
app.get('/login', (req, res) => {
  res.render('login', { error: null, user: req.session.user });
});

app.post('/login', async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });


  const { error } = schema.validate(req.body);
  if (error) return res.render('login', { error: error.details[0].message, user: req.session.user });

  const user = await db.collection('users').findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.render('login', { error: 'Invalid email or password', user: req.session.user });
  }

  req.session.user = { name: user.name, email: user.email };
  res.redirect('/members');
})

app.get('/members', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const images = ['img1.jpg', 'img2.jpg', 'img3.jpg'];
  res.render('members', { user: req.session.user, images });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/admin', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const user = await db.collection('users').findOne({ email: req.session.user.email });
  if (!user || user.type !== 'admin') {
    return res.status(403).render('403', {
  message: "You are not authorized.",
  user: req.session.user
});

  }

  const users = await db.collection('users').find().toArray();
  res.render('admin', {
    users,
    user: req.session.user
  });
});

app.get('/promote/:email', async (req, res) => {
  await db.collection('users').updateOne({ email: req.params.email }, { $set: { type: 'admin' } });
  res.redirect('/admin');
});

app.get('/demote/:email', async (req, res) => {
  await db.collection('users').updateOne({ email: req.params.email }, { $set: { type: 'user' } });
  res.redirect('/admin');
});

app.use((req, res) => {
  res.status(404).render('404', {
    user: req.session.user || null
  });
});
