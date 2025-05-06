require('dotenv').config();
console.log('Session secret is:', process.env.NODE_SESSION_SECRET);

const express = require('express');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient, ServerApiVersion } = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const app = express();

const uri =
  `mongodb+srv://${process.env.MONGODB_USER}` +
  `:${encodeURIComponent(process.env.MONGODB_PASSWORD)}` +
  `@${process.env.MONGODB_HOST}` +
  `/${process.env.MONGODB_DATABASE}` +
  `?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

const signupInfo = Joi.object({
  name: Joi.string().max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});
const loginInfo = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

async function start() {
  try {

    await client.connect();
    console.log('Connected to MongoDB Atlas!');

    app.use(
      session({
        secret: process.env.NODE_SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        store: MongoStore.create({
          client,
          dbName: process.env.MONGODB_DATABASE,
          collectionName: 'sessions',
          crypto: { secret: process.env.MONGODB_SESSION_SECRET },
          ttl: 60 * 60,
        }),
        cookie: { maxAge: 1000 * 60 * 60 }
      })
    );

    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
    app.use(express.static(path.join(__dirname, 'public')));
    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, 'views'));

    app.get('/', (req, res) => {
      if (req.session.name) {
        return res.render('index', {
          loggedIn: true,
          name: req.session.name
        });
      }
      res.render('index', { loggedIn: false });
    });

    app.get('/signup', (req, res) => {
      res.render('signup');
    });

    app.post('/signup', async (req, res) => {
      const { error, value } = signupInfo.validate(req.body);
      if (error) {
        return res.send(`<p>${error.message}</p><a href="/signup">Try again</a>`);
      }
      const { name, email, password } = value;
      const hash = await bcrypt.hash(password, 10);
      await client.db().collection('users')
        .insertOne({ name, email, password: hash });
      req.session.name = name;
      res.redirect('/members');
    });

    app.get('/login', (req, res) => {
      res.render('login');
    });

    app.post('/login', async (req, res) => {
      const { error, value } = loginInfo.validate(req.body);
      if (error) {
        return res.send(`<p>${error.message}</p><a href="/login">Try again</a>`);
      }
      const { email, password } = value;
      const user = await client.db().collection('users').findOne({ email });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.send('<p>Invalid password</p><a href="/login">Try again</a>');
      }
      req.session.name = user.name;
      res.redirect('/members');
    });

    app.get('/members', (req, res) => {
      if (!req.session.name) return res.redirect('/');

      const images = [
        '/img/CatImage-1.jpg',
        '/img/CatImage-2.jpg',
        '/img/CatImage-3.jpg'
      ];

      const image = images[Math.floor(Math.random() * images.length)];
      res.render('members', {
        name: req.session.name,
        image
      });
    });


    app.get('/logout', (req, res) => {
      req.session.destroy(() => res.redirect('/'));
    });

    app.use((req, res) => {
      res.status(404).render('404');
    });
    const PORT = process.env.PORT || 8001;
    app.listen(PORT, () =>
      console.log(`Server listening on http://localhost:${PORT}`)
    );

  } catch (err) {
    console.error('Failed to start server:', err);
  }
}

start();
