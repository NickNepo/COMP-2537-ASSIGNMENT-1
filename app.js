require('dotenv').config();
console.log('Session secret is:', process.env.NODE_SESSION_SECRET);

const express = require('express');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const {
  MongoClient,
  ServerApiVersion,
  ObjectId
} = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const app = express();



function checkLogin(req, res, next) {
  if (!req.session.name) {
    return res.redirect('/login');
  }
  next();
}

function checkAdmin(req, res, next) {
  if (req.session.user_type !== 'admin') {
    return res.status(403).render('403', { title: '403 Access Denied' });
  }
  next();
}

const idSchema = Joi.string()
  .length(24)
  .hex()
  .required();
const signupSchema = Joi.object({
  name: Joi.string().max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

async function start() {
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
      deprecationErrors: true
    }
  });

  try {
    await client.connect();
    console.log('Connected to MongoDB Atlas!');

    app.use(session({
      secret: process.env.NODE_SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        client,
        dbName: process.env.MONGODB_DATABASE,
        collectionName: 'sessions',
        crypto: { secret: process.env.MONGODB_SESSION_SECRET },
        ttl: 60 * 60
      }),
      cookie: { maxAge: 1000 * 60 * 60 }
    }));

    app.use((req, res, next) => {
      res.locals.loggedIn = !!req.session.name;
      res.locals.name = req.session.name;
      res.locals.user_type = req.session.user_type;
      next();
    });

    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
    app.use(express.static(path.join(__dirname, 'public')));
    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, 'views'));

    app.get('/', (req, res) => {
      res.render('index', { title: 'Home' });
    });

    app.get('/signup', (req, res) => {
      res.render('signup', { title: 'Sign Up' });
    });
    app.post('/signup', async (req, res) => {
      const { error, value } = signupSchema.validate(req.body);
      if (error) {
        return res.send(`<p>${error.message}</p><a href="/signup">Try again</a>`);
      }
      const { name, email, password } = value;
      const hash = await bcrypt.hash(password, 10);
      await client.db().collection('users')
        .insertOne({ name, email, password: hash, user_type: 'user' });
      req.session.name = name;
      req.session.user_type = 'user';
      res.redirect('/members');
    });

    app.get('/login', (req, res) => {
      res.render('login', { title: 'Log In' });
    });
    app.post('/login', async (req, res) => {
      const { error, value } = loginSchema.validate(req.body);
      if (error) {
        return res.send(`<p>${error.message}</p><a href="/login">Try again</a>`);
      }
      const { email, password } = value;
      const user = await client.db().collection('users').findOne({ email });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.send('<p>Invalid credentials</p><a href="/login">Try again</a>');
      }
      req.session.name = user.name;
      req.session.user_type = user.user_type;
      res.redirect('/members');
    });

    app.get(
      '/members',
      checkLogin,
      (req, res) => {
        const images = [
          '/img/CatImage-1.jpg',
          '/img/CatImage-2.jpg',
          '/img/CatImage-3.jpg'
        ];
        res.render('members', {
          title: 'Members Area',
          images
        });
      }
    );

    app.get(
      '/admin',
      checkLogin, checkAdmin,
      async (req, res) => {
        const users = await client.db().collection('users').find().toArray();
        res.render('admin', {
          title: 'Admin Dashboard',
          users
        });
      }
    );

    app.get(
      '/admin/promote/:id',
      checkLogin, checkAdmin,
      async (req, res) => {
        const { error, value: id } = idSchema.validate(req.params.id);
        if (error) {
          return res
            .status(400)
            .send(`<p>Invalid user ID</p><a href="/admin">Back to Admin</a>`);
        }
        await client.db().collection('users')
          .updateOne(
            { _id: new ObjectId(id) },
            { $set: { user_type: 'admin' } }
          );
        res.redirect('/admin');
      }
    );

    app.get(
      '/admin/demote/:id',
      checkLogin, checkAdmin,
      async (req, res) => {
        const { error, value: id } = idSchema.validate(req.params.id);
        if (error) {
          return res
            .status(400)
            .send(`<p>Invalid user ID</p><a href="/admin">Back to Admin</a>`);
        }
        await client.db().collection('users')
          .updateOne(
            { _id: new ObjectId(id) },
            { $set: { user_type: 'user' } }
          );
        res.redirect('/admin');
      }
    );

    app.get('/logout', (req, res) => {
      req.session.destroy(() => res.redirect('/'));
    });

    app.use((req, res) => {
      res.status(404).render('404', {
        title: '404 – Not Found',
        url: req.originalUrl
      });
    });
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () =>
      console.log(`Server listening on http://localhost:${PORT}`)
    );

  } catch (err) {
    console.error('Failed to start server:', err);
  }
}

start();
