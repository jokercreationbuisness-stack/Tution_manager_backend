const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json());

const {
  MONGODB_URI = 'mongodb://localhost:27017',
  DB_NAME = 'tuitionmanager',
  JWT_SECRET = 'dev_secret',
  PORT = 3001
} = process.env;

/* ========= Mongo Connection ========= */
mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI, { dbName: DB_NAME })
  .then(() => console.log('Mongo connected'))
  .catch(err => { console.error('Mongo connect error', err); process.exit(1); });

/* ========= Health ========= */
app.get('/health', (_req, res) => res.json({ ok: true }));

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => {
  console.log(`Server listening on :${PORT}`);
});
