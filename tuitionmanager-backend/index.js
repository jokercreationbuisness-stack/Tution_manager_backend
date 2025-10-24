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

/* ========= Schemas & Models ========= */
const { Schema, Types } = mongoose;

const UserSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, lowercase: true, unique: true, index: true },
  mobile: { type: String },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['STUDENT', 'TEACHER'], required: true },
  studentCode: { type: String, unique: true, sparse: true, index: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const TeacherStudentLinkSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  createdAt: { type: Date, default: Date.now }
});
TeacherStudentLinkSchema.index({ teacherId: 1, studentId: 1 }, { unique: true });
const TeacherStudentLink = mongoose.model('TeacherStudentLink', TeacherStudentLinkSchema);

/* ========= Health ========= */
app.get('/health', (_req, res) => res.json({ ok: true }));

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => {
  console.log(`Server listening on :${PORT}`);
});
