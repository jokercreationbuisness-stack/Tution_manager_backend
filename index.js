const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

const {
  MONGODB_URI = 'mongodb://localhost:27017',
  DB_NAME = 'tuitionmanager',
  JWT_SECRET = 'dev_secret',
  PORT = 3001
} = process.env;

// MongoDB connection
mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI, { dbName: DB_NAME })
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => {
    console.error('MongoDB connection failed:', err);
    process.exit(1);
  });

// Health check route
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Default route
app.get('/', (req, res) => res.send('Tuition Manager Backend Running'));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
