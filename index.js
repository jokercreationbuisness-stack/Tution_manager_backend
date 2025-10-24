const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json());

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'tuitionmanager';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const PORT = parseInt(process.env.PORT, 10) || 3001; // Convert to number


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

const ClassSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  subject: { type: String, required: true },
  dayOfWeek: { type: Number, required: true }, // 1-7
  startTime: { type: String, required: true }, // HH:mm
  endTime: { type: String, required: true },   // HH:mm
  colorHex: { type: String },
  notes: { type: String },
  location: { type: String },
  createdAt: { type: Date, default: Date.now }
});
const ClassModel = mongoose.model('Class', ClassSchema);

const AssignmentSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  dueAt: { type: String }, // ISO-8601 (string)
  classId: { type: String }, // optional: store as string ID
  notes: { type: String },
  priority: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const Assignment = mongoose.model('Assignment', AssignmentSchema);

const NoteSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  content: { type: String },
  subject: { type: String },
  createdAt: { type: Date, default: Date.now }
});
const Note = mongoose.model('Note', NoteSchema);

const ExamSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  whenAt: { type: String, required: true }, // ISO-8601 (string)
  classId: { type: String },
  location: { type: String },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now }
});
const Exam = mongoose.model('Exam', ExamSchema);

/* ========= Helpers ========= */
function nowIso() {
  return new Date().toISOString();
}
function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: '30d' });
}
function authRequired(req, res, next) {
  const auth = req.headers.authorization || '';
  const [bearer, token] = auth.split(' ');
  if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    req.role = payload.role;
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}
function generateStudentCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += alphabet[Math.floor(Math.random() * alphabet.length)];
  return code;
}

/* ========= Auth ========= */
// POST /api/auth/signup -> { token, userId }
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, mobile, password, role } = req.body || {};
    if (!name || !email || !password || !['STUDENT', 'TEACHER'].includes(role)) {
      return res.status(400).json({ error: 'Invalid payload' });
    }
    const exists = await User.findOne({ email: email.toLowerCase() }).lean();
    if (exists) return res.status(409).json({ error: 'Email already used' });

    const passwordHash = bcrypt.hashSync(password, 10);
    const user = await User.create({
      name,
      email: email.toLowerCase(),
      mobile: mobile || null,
      passwordHash,
      role,
      createdAt: nowIso()
    });
    const token = signToken(user);
    return res.json({ token, userId: user._id.toString() });
  } catch (e) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/login -> { token, userId }
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Invalid payload' });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = bcrypt.compareSync(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken(user);
    return res.json({ token, userId: user._id.toString() });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Student ========= */
// GET /api/student/code -> { code }
app.get('/api/student/code', authRequired, async (req, res) => {
  try {
    if (req.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const user = await User.findById(req.userId);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });

    if (!user.studentCode) {
      // generate unique code
      let code, collision;
      do {
        code = generateStudentCode();
        // sparse unique index used; check manually to avoid dup
        collision = await User.findOne({ studentCode: code }).lean();
      } while (collision);
      user.studentCode = code;
      await user.save();
      return res.json({ code });
    }
    return res.json({ code: user.studentCode });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Teacher: link/list students ========= */
// POST /api/teacher/link-student { code }
app.post('/api/teacher/link-student', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ error: 'Code required' });
    const student = await User.findOne({ studentCode: code, role: 'STUDENT' }).lean();
    if (!student) return res.status(404).json({ error: 'Student not found' });

    await TeacherStudentLink.updateOne(
      { teacherId: req.userId, studentId: student._id },
      { $setOnInsert: { teacherId: req.userId, studentId: student._id, createdAt: nowIso() } },
      { upsert: true }
    );
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/teacher/students -> [{ id, name, email, mobile }]
app.get('/api/teacher/students', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const links = await TeacherStudentLink.find({ teacherId: req.userId })
      .populate('studentId', 'name email mobile')
      .lean();

    const result = links.map(l => ({
      id: l.studentId._id.toString(),
      name: l.studentId.name,
      email: l.studentId.email,
      mobile: l.studentId.mobile || null
    }));
    return res.json(result);
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Teacher: Classes ========= */
// POST /api/teacher/classes
app.post('/api/teacher/classes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { subject, dayOfWeek, startTime, endTime, colorHex, notes, location } = req.body || {};
    if (!subject || !dayOfWeek || !startTime || !endTime) return res.status(400).json({ error: 'Invalid payload' });

    await ClassModel.create({
      teacherId: req.userId,
      subject, dayOfWeek, startTime, endTime,
      colorHex: colorHex || null,
      notes: notes || null,
      location: location || null,
      createdAt: nowIso()
    });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/teacher/classes -> [{ id, subject, dayOfWeek, startTime, endTime }]
app.get('/api/teacher/classes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await ClassModel.find({ teacherId: req.userId }, 'subject dayOfWeek startTime endTime').sort({ createdAt: -1 }).lean();
    return res.json(rows.map(r => ({
      id: r._id.toString(),
      subject: r.subject,
      dayOfWeek: r.dayOfWeek,
      startTime: r.startTime,
      endTime: r.endTime
    }));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/teacher/classes/:id
app.put('/api/teacher/classes/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const update = {};
    const keys = ['subject','dayOfWeek','startTime','endTime','colorHex','notes','location'];
    for (const k of keys) if (k in req.body) update[k] = req.body[k];

    const doc = await ClassModel.findOneAndUpdate({ _id: id, teacherId: req.userId }, update, { new: false });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/teacher/classes/:id
app.delete('/api/teacher/classes/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const result = await ClassModel.deleteOne({ _id: id, teacherId: req.userId });
    if (!result.deletedCount) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Teacher: Assignments ========= */
// POST /api/teacher/assignments
app.post('/api/teacher/assignments', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { title, dueAt, classId, notes, priority } = req.body || {};
    if (!title) return res.status(400).json({ error: 'Title required' });
    await Assignment.create({
      teacherId: req.userId,
      title,
      dueAt: dueAt || null,
      classId: classId || null,
      notes: notes || null,
      priority: Number.isInteger(priority) ? priority : 0,
      createdAt: nowIso()
    });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/teacher/assignments -> [{ id, title, dueAt }]
app.get('/api/teacher/assignments', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await Assignment.find({ teacherId: req.userId }, 'title dueAt').sort({ createdAt: -1 }).lean();
    return res.json(rows.map(r => ({ id: r._id.toString(), title: r.title, dueAt: r.dueAt || null })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/teacher/assignments/:id
app.put('/api/teacher/assignments/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const update = {};
    const keys = ['title','dueAt','classId','notes','priority'];
    for (const k of keys) if (k in req.body) update[k] = req.body[k];

    const doc = await Assignment.findOneAndUpdate({ _id: id, teacherId: req.userId }, update, { new: false });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/teacher/assignments/:id
app.delete('/api/teacher/assignments/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const result = await Assignment.deleteOne({ _id: id, teacherId: req.userId });
    if (!result.deletedCount) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Teacher: Notes ========= */
// POST /api/teacher/notes
app.post('/api/teacher/notes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { title, content, subject } = req.body || {};
    if (!title) return res.status(400).json({ error: 'Title required' });
    await Note.create({
      teacherId: req.userId,
      title,
      content: content || null,
      subject: subject || null,
      createdAt: nowIso()
    });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/teacher/notes -> [{ id, title }]
app.get('/api/teacher/notes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await Note.find({ teacherId: req.userId }, 'title').sort({ createdAt: -1 }).lean();
    return res.json(rows.map(r => ({ id: r._id.toString(), title: r.title })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/teacher/notes/:id
app.put('/api/teacher/notes/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const update = {};
    const keys = ['title','content','subject'];
    for (const k of keys) if (k in req.body) update[k] = req.body[k];

    const doc = await Note.findOneAndUpdate({ _id: id, teacherId: req.userId }, update, { new: false });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/teacher/notes/:id
app.delete('/api/teacher/notes/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const result = await Note.deleteOne({ _id: id, teacherId: req.userId });
    if (!result.deletedCount) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Teacher: Exams ========= */
// POST /api/teacher/exams
app.post('/api/teacher/exams', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { title, whenAt, classId, location, notes } = req.body || {};
    if (!title || !whenAt) return res.status(400).json({ error: 'Invalid payload' });
    await Exam.create({
      teacherId: req.userId,
      title, whenAt,
      classId: classId || null,
      location: location || null,
      notes: notes || null,
      createdAt: nowIso()
    });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/teacher/exams -> [{ id, title, whenAt }]
app.get('/api/teacher/exams', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await Exam.find({ teacherId: req.userId }, 'title whenAt').sort({ createdAt: -1 }).lean();
    return res.json(rows.map(r => ({ id: r._id.toString(), title: r.title, whenAt: r.whenAt })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/teacher/exams/:id
app.put('/api/teacher/exams/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const update = {};
    const keys = ['title','whenAt','classId','location','notes'];
    for (const k of keys) if (k in req.body) update[k] = req.body[k];

    const doc = await Exam.findOneAndUpdate({ _id: id, teacherId: req.userId }, update, { new: false });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/teacher/exams/:id
app.delete('/api/teacher/exams/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const result = await Exam.deleteOne({ _id: id, teacherId: req.userId });
    if (!result.deletedCount) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Health ========= */
app.get('/health', (_req, res) => res.json({ ok: true }));

/* ========= Fallback ========= */
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => {
  console.log(`Server listening on :${PORT}`);
});
