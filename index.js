// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json());

// Config
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'tuitionmanager';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const PORT = parseInt(process.env.PORT, 10) || 3001;

// Mongo
mongoose.set('strictQuery', true);
mongoose
  .connect(MONGODB_URI, { dbName: DB_NAME })
  .then(() => console.log('Mongo connected'))
  .catch((err) => { console.error('Mongo connect error', err); process.exit(1); });

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

// Classes can optionally be scoped to a single student
const ClassSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  subject: { type: String, required: true },
  dayOfWeek: { type: Number, required: true }, // 1-7
  startTime: { type: String, required: true }, // HH:mm
  endTime: { type: String, required: true },   // HH:mm
  colorHex: { type: String },
  notes: { type: String },
  location: { type: String },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User', default: null },
  createdAt: { type: Date, default: Date.now }
});
const ClassModel = mongoose.model('Class', ClassSchema);

// Assignments/Notes/Exams can be scoped to a specific student
const AssignmentSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  dueAt: { type: String }, // ISO-8601 (string)
  classId: { type: String }, // store as string ID
  notes: { type: String },
  priority: { type: Number, default: 0 },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User', default: null },
  createdAt: { type: Date, default: Date.now }
});
const Assignment = mongoose.model('Assignment', AssignmentSchema);

const NoteSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  content: { type: String },
  subject: { type: String },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User', default: null },
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
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User', default: null },
  createdAt: { type: Date, default: Date.now }
});
const Exam = mongoose.model('Exam', ExamSchema);

// Results (marks & remarks)
const ResultSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  examId: { type: String, default: null }, // optional cross-ref to Exam _id string
  examTitle: { type: String, required: true },
  subject: { type: String, default: null },
  totalMarks: { type: Number, required: true },
  obtainedMarks: { type: Number, required: true },
  remarks: { type: String, default: null },
  createdAt: { type: Date, default: Date.now }
});
const Result = mongoose.model('Result', ResultSchema);

// Attendance: per class per date; marks is a list of student presence
const AttendanceSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  classId: { type: String, required: true }, // Class id (string)
  date: { type: String, required: true },    // yyyy-MM-dd
  marks: [
    {
      studentId: { type: Types.ObjectId, ref: 'User', required: true },
      present: { type: Boolean, required: true }
    }
  ],
  createdAt: { type: Date, default: Date.now }
});
AttendanceSchema.index({ teacherId: 1, classId: 1, date: 1 }, { unique: true });
const Attendance = mongoose.model('Attendance', AttendanceSchema);

/* ========= Helpers ========= */
function nowIso() { return new Date().toISOString(); }
function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
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
  } catch { return res.status(401).json({ error: 'Unauthorized' }); }
}
function generateStudentCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += alphabet[Math.floor(Math.random() * alphabet.length)];
  return code;
}
function pad2(n) { return (n < 10 ? '0' : '') + n; }
function defaultEndTime(startHHmm) {
  if (!startHHmm || !/^\d{2}:\d{2}$/.test(startHHmm)) return startHHmm || '00:00';
  const [hh, mm] = startHHmm.split(':').map((x) => parseInt(x, 10));
  const endH = (hh + 1) % 24;
  return pad2(endH) + ':' + pad2(mm);
}
async function ensureTeacherOwnsStudent(teacherId, studentId) {
  const link = await TeacherStudentLink.findOne({ teacherId, studentId }).lean();
  return !!link;
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
  } catch {
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

/* ========= Student: Fetch Data (needed by student dashboard) ========= */
// GET /api/student/teachers
app.get('/api/student/teachers', authRequired, async (req, res) => {
  try {
    if (req.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const links = await TeacherStudentLink.find({ studentId: req.userId })
      .populate('teacherId', 'name email mobile')
      .lean();
    return res.json(
      links.map((l) => ({
        id: l.teacherId._id.toString(),
        name: l.teacherId.name,
        email: l.teacherId.email,
        mobile: l.teacherId.mobile || null
      }))
    );
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/student/classes
app.get('/api/student/classes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const links = await TeacherStudentLink.find({ studentId: req.userId }).lean();
    const teacherIds = links.map((l) => l.teacherId);
    const classes = await ClassModel.find({
      teacherId: { $in: teacherIds },
      $or: [{ scope: 'ALL' }, { scope: 'INDIVIDUAL', studentId: req.userId }]
    }).sort({ dayOfWeek: 1, startTime: 1 }).lean();
    return res.json(
      classes.map((c) => ({
        id: c._id.toString(),
        subject: c.subject,
        dayOfWeek: c.dayOfWeek,
        startTime: c.startTime,
        endTime: c.endTime,
        colorHex: c.colorHex || null,
        notes: c.notes || null,
        location: c.location || null
      }))
    );
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/student/assignments
app.get('/api/student/assignments', authRequired, async (req, res) => {
  try {
    if (req.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const links = await TeacherStudentLink.find({ studentId: req.userId }).lean();
    const teacherIds = links.map((l) => l.teacherId);
    const assignments = await Assignment.find({
      teacherId: { $in: teacherIds },
      $or: [{ scope: 'ALL' }, { scope: 'INDIVIDUAL', studentId: req.userId }]
    }).sort({ dueAt: 1, createdAt: -1 }).lean();
    return res.json(
      assignments.map((a) => ({
        id: a._id.toString(),
        title: a.title,
        dueAt: a.dueAt || null,
        classId: a.classId || null,
        notes: a.notes || null,
        priority: a.priority || 0
      }))
    );
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/student/notes
app.get('/api/student/notes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const links = await TeacherStudentLink.find({ studentId: req.userId }).lean();
    const teacherIds = links.map((l) => l.teacherId);
    const notes = await Note.find({
      teacherId: { $in: teacherIds },
      $or: [{ scope: 'ALL' }, { scope: 'INDIVIDUAL', studentId: req.userId }]
    }).sort({ createdAt: -1 }).lean();
    return res.json(
      notes.map((n) => ({
        id: n._id.toString(),
        title: n.title,
        content: n.content || null,
        subject: n.subject || null
      }))
    );
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/student/exams
app.get('/api/student/exams', authRequired, async (req, res) => {
  try {
    if (req.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const links = await TeacherStudentLink.find({ studentId: req.userId }).lean();
    const teacherIds = links.map((l) => l.teacherId);
    const exams = await Exam.find({
      teacherId: { $in: teacherIds },
      $or: [{ scope: 'ALL' }, { scope: 'INDIVIDUAL', studentId: req.userId }]
    }).sort({ whenAt: 1 }).lean();
    return res.json(
      exams.map((e) => ({
        id: e._id.toString(),
        title: e.title,
        whenAt: e.whenAt,
        classId: e.classId || null,
        location: e.location || null,
        notes: e.notes || null
      }))
    );
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/student/results
app.get('/api/student/results', authRequired, async (req, res) => {
  try {
    if (req.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const results = await Result.find({ studentId: req.userId }).sort({ createdAt: -1 }).lean();
    return res.json(
      results.map((r) => ({
        id: r._id.toString(),
        examTitle: r.examTitle,
        subject: r.subject || null,
        totalMarks: r.totalMarks,
        obtainedMarks: r.obtainedMarks,
        remarks: r.remarks || null,
        createdAt: r.createdAt?.toISOString?.() || new Date(r.createdAt).toISOString()
      }))
    );
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Teacher: link/list/unlink students ========= */
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

// GET /api/teacher/students -> [{ id, name, email, mobile, code }]
app.get('/api/teacher/students', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const links = await TeacherStudentLink.find({ teacherId: req.userId })
      .populate('studentId', 'name email mobile studentCode')
      .lean();

    const result = links.map((l) => ({
      id: l.studentId._id.toString(),
      name: l.studentId.name,
      email: l.studentId.email,
      mobile: l.studentId.mobile || null,
      code: l.studentId.studentCode || null
    }));
    return res.json(result);
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/teacher/students/:id
app.delete('/api/teacher/students/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const studentId = req.params.id;
    const del = await TeacherStudentLink.deleteOne({ teacherId: req.userId, studentId });
    if (!del.deletedCount) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Teacher: Classes ========= */
// POST /api/teacher/classes
app.post('/api/teacher/classes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    let { subject, dayOfWeek, startTime, endTime, colorHex, notes, location, scope, studentId, studentCode } = req.body || {};
    if (!subject || !dayOfWeek || !startTime) return res.status(400).json({ error: 'Invalid payload' });
    if (!endTime) endTime = defaultEndTime(startTime);

    // Resolve student by id or code if INDIVIDUAL
    let linkedStudentId = null;
    if (scope === 'INDIVIDUAL') {
      if (!studentId && studentCode) {
        const s = await User.findOne({ studentCode, role: 'STUDENT' }).lean();
        if (!s) return res.status(404).json({ error: 'Student not found' });
        linkedStudentId = s._id;
      } else if (studentId) {
        linkedStudentId = studentId;
      }
      if (linkedStudentId) {
        const ok = await ensureTeacherOwnsStudent(req.userId, linkedStudentId);
        if (!ok) return res.status(403).json({ error: 'Not linked to student' });
      }
    }

    await ClassModel.create({
      teacherId: req.userId,
      subject,
      dayOfWeek,
      startTime,
      endTime,
      colorHex: colorHex || null,
      notes: notes || null,
      location: location || null,
      scope: scope === 'INDIVIDUAL' ? 'INDIVIDUAL' : 'ALL',
      studentId: linkedStudentId || null,
      createdAt: nowIso()
    });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/teacher/classes
app.get('/api/teacher/classes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await ClassModel.find({ teacherId: req.userId })
      .sort({ dayOfWeek: 1, startTime: 1 }).lean();

    // populate student name for individual classes
    const individual = rows.filter(r => r.scope === 'INDIVIDUAL' && r.studentId);
    const studentIds = [...new Set(individual.map(r => r.studentId.toString()))];
    const students = studentIds.length
      ? await User.find({ _id: { $in: studentIds } }, 'name').lean()
      : [];
    const nameMap = new Map(students.map(s => [s._id.toString(), s.name]));

    return res.json(rows.map(r => ({
      id: r._id.toString(),
      subject: r.subject,
      dayOfWeek: r.dayOfWeek,
      startTime: r.startTime,
      endTime: r.endTime,
      colorHex: r.colorHex || null,
      notes: r.notes || null,
      location: r.location || null,
      scope: r.scope || 'ALL',
      studentId: r.studentId ? r.studentId.toString() : null,
      studentName: r.studentId ? (nameMap.get(r.studentId.toString()) || null) : null
    })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/teacher/classes/:id
app.put('/api/teacher/classes/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const body = req.body || {};
    const update = {};
    const keys = ['subject', 'dayOfWeek', 'startTime', 'endTime', 'colorHex', 'notes', 'location', 'scope'];
    for (const k of keys) if (k in body) update[k] = body[k];
    if (update.startTime && !update.endTime) update.endTime = defaultEndTime(update.startTime);

    // Handle student link updates via studentId or studentCode
    if (('scope' in body && body.scope === 'ALL')) {
      update.studentId = null;
    }
    let desiredStudentId = null;
    if (body.scope === 'INDIVIDUAL') {
      if (body.studentId) desiredStudentId = body.studentId;
      else if (body.studentCode) {
        const s = await User.findOne({ studentCode: body.studentCode, role: 'STUDENT' }).lean();
        if (!s) return res.status(404).json({ error: 'Student not found' });
        desiredStudentId = s._id.toString();
      }
      if (desiredStudentId) {
        const ok = await ensureTeacherOwnsStudent(req.userId, desiredStudentId);
        if (!ok) return res.status(403).json({ error: 'Not linked to student' });
        update.studentId = desiredStudentId;
        update.scope = 'INDIVIDUAL';
      }
    }

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
app.post('/api/teacher/assignments', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { title, dueAt, classId, notes, priority, scope, studentId } = req.body || {};
    if (!title) return res.status(400).json({ error: 'Title required' });

    if (scope === 'INDIVIDUAL' && studentId) {
      const ok = await ensureTeacherOwnsStudent(req.userId, studentId);
      if (!ok) return res.status(403).json({ error: 'Not linked to student' });
    }
    await Assignment.create({
      teacherId: req.userId,
      title,
      dueAt: dueAt || null,
      classId: classId || null,
      notes: notes || null,
      priority: Number.isInteger(priority) ? priority : 0,
      scope: scope === 'INDIVIDUAL' ? 'INDIVIDUAL' : 'ALL',
      studentId: scope === 'INDIVIDUAL' ? (studentId || null) : null,
      createdAt: nowIso()
    });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/teacher/assignments', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await Assignment.find({ teacherId: req.userId }, 'title dueAt').sort({ createdAt: -1 }).lean();
    return res.json(rows.map((r) => ({ id: r._id.toString(), title: r.title, dueAt: r.dueAt || null })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/teacher/assignments/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const update = {};
    const keys = ['title', 'dueAt', 'classId', 'notes', 'priority', 'scope', 'studentId'];
    for (const k of keys) if (k in req.body) update[k] = req.body[k];
    if (update.scope === 'INDIVIDUAL' && update.studentId) {
      const ok = await ensureTeacherOwnsStudent(req.userId, update.studentId);
      if (!ok) return res.status(403).json({ error: 'Not linked to student' });
    }
    const doc = await Assignment.findOneAndUpdate({ _id: id, teacherId: req.userId }, update, { new: false });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

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
app.post('/api/teacher/notes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { title, content, subject, scope, studentId } = req.body || {};
    if (!title) return res.status(400).json({ error: 'Title required' });

    if (scope === 'INDIVIDUAL' && studentId) {
      const ok = await ensureTeacherOwnsStudent(req.userId, studentId);
      if (!ok) return res.status(403).json({ error: 'Not linked to student' });
    }
    await Note.create({
      teacherId: req.userId,
      title,
      content: content || null,
      subject: subject || null,
      scope: scope === 'INDIVIDUAL' ? 'INDIVIDUAL' : 'ALL',
      studentId: scope === 'INDIVIDUAL' ? (studentId || null) : null,
      createdAt: nowIso()
    });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/teacher/notes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await Note.find({ teacherId: req.userId }, 'title').sort({ createdAt: -1 }).lean();
    return res.json(rows.map((r) => ({ id: r._id.toString(), title: r.title })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/teacher/notes/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const update = {};
    const keys = ['title', 'content', 'subject', 'scope', 'studentId'];
    for (const k of keys) if (k in req.body) update[k] = req.body[k];
    if (update.scope === 'INDIVIDUAL' && update.studentId) {
      const ok = await ensureTeacherOwnsStudent(req.userId, update.studentId);
      if (!ok) return res.status(403).json({ error: 'Not linked to student' });
    }
    const doc = await Note.findOneAndUpdate({ _id: id, teacherId: req.userId }, update, { new: false });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

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
app.post('/api/teacher/exams', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { title, whenAt, classId, location, notes, scope, studentId } = req.body || {};
    if (!title || !whenAt) return res.status(400).json({ error: 'Invalid payload' });

    if (scope === 'INDIVIDUAL' && studentId) {
      const ok = await ensureTeacherOwnsStudent(req.userId, studentId);
      if (!ok) return res.status(403).json({ error: 'Not linked to student' });
    }
    await Exam.create({
      teacherId: req.userId,
      title,
      whenAt,
      classId: classId || null,
      location: location || null,
      notes: notes || null,
      scope: scope === 'INDIVIDUAL' ? 'INDIVIDUAL' : 'ALL',
      studentId: scope === 'INDIVIDUAL' ? (studentId || null) : null,
      createdAt: nowIso()
    });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/teacher/exams', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await Exam.find({ teacherId: req.userId }, 'title whenAt').sort({ createdAt: -1 }).lean();
    return res.json(rows.map((r) => ({ id: r._id.toString(), title: r.title, whenAt: r.whenAt })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/teacher/exams/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const update = {};
    const keys = ['title', 'whenAt', 'classId', 'location', 'notes', 'scope', 'studentId'];
    for (const k of keys) if (k in req.body) update[k] = req.body[k];
    if (update.scope === 'INDIVIDUAL' && update.studentId) {
      const ok = await ensureTeacherOwnsStudent(req.userId, update.studentId);
      if (!ok) return res.status(403).json({ error: 'Not linked to student' });
    }
    const doc = await Exam.findOneAndUpdate({ _id: id, teacherId: req.userId }, update, { new: false });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

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

/* ========= Teacher: Results ========= */
// POST /api/teacher/results
app.post('/api/teacher/results', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const {
      studentCode,
      examTitle,
      examId,
      subject,
      totalMarks,
      obtainedMarks,
      remarks,
      scope,       // ignored for results; always individual
      studentId
    } = req.body || {};

    if (!examTitle || totalMarks == null || obtainedMarks == null) {
      return res.status(400).json({ error: 'Invalid payload' });
    }

    // Resolve student by code or id
    let student = null;
    if (studentId) student = await User.findOne({ _id: studentId, role: 'STUDENT' });
    if (!student && studentCode) student = await User.findOne({ studentCode: studentCode, role: 'STUDENT' });
    if (!student) return res.status(400).json({ error: 'Student not specified' });

    const ok = await ensureTeacherOwnsStudent(req.userId, student._id);
    if (!ok) return res.status(403).json({ error: 'Not linked to student' });

    await Result.create({
      teacherId: req.userId,
      studentId: student._id,
      examId: examId || null,
      examTitle,
      subject: subject || null,
      totalMarks: Number(totalMarks),
      obtainedMarks: Number(obtainedMarks),
      remarks: remarks || null,
      createdAt: nowIso()
    });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/teacher/results
app.get('/api/teacher/results', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await Result.find({ teacherId: req.userId }).sort({ createdAt: -1 }).lean();
    const studentIds = [...new Set(rows.map((r) => r.studentId?.toString()))].filter(Boolean);
    const students = await User.find({ _id: { $in: studentIds } }, 'studentCode name').lean();
    const codeMap = new Map(students.map((s) => [s._id.toString(), s.studentCode || '']));
    const nameMap = new Map(students.map((s) => [s._id.toString(), s.name || null]));
    return res.json(
      rows.map((r) => ({
        id: r._id.toString(),
        studentName: nameMap.get(r.studentId?.toString()) || null,
        studentCode: codeMap.get(r.studentId?.toString()) || '',
        examTitle: r.examTitle,
        subject: r.subject || null,
        totalMarks: r.totalMarks,
        obtainedMarks: r.obtainedMarks,
        remarks: r.remarks || null,
        createdAt: r.createdAt?.toISOString?.() || new Date(r.createdAt).toISOString()
      }))
    );
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/teacher/results/:id
app.put('/api/teacher/results/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const update = {};
    const keys = ['examTitle', 'examId', 'subject', 'totalMarks', 'obtainedMarks', 'remarks'];
    for (const k of keys) if (k in req.body) update[k] = req.body[k];
    const doc = await Result.findOneAndUpdate({ _id: id, teacherId: req.userId }, update, { new: false });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/teacher/results/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const del = await Result.deleteOne({ _id: id, teacherId: req.userId });
    if (!del.deletedCount) return res.status(404).json({ error: 'Not found' });
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Attendance ========= */
// POST /api/teacher/attendance
// Body: { classId: string, date: yyyy-MM-dd, marks: [{ studentId, present }] }
app.post('/api/teacher/attendance', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { classId, date, marks } = req.body || {};
    if (!classId || !date || !Array.isArray(marks)) return res.status(400).json({ error: 'Invalid payload' });

    // validate class belongs to teacher
    const cls = await ClassModel.findOne({ _id: classId, teacherId: req.userId }).lean();
    if (!cls) return res.status(404).json({ error: 'Class not found' });

    // validate each student link
    for (const m of marks) {
      if (!m || !m.studentId) continue;
      const ok = await ensureTeacherOwnsStudent(req.userId, m.studentId);
      if (!ok) return res.status(403).json({ error: 'Not linked to student ' + m.studentId });
    }

    // Upsert per teacher+class+date
    await Attendance.updateOne(
      { teacherId: req.userId, classId, date },
      { $set: { marks, createdAt: nowIso() } },
      { upsert: true }
    );
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Teacher analytics per student ========= */
// GET /api/teacher/analytics/:studentId -> { attended, missed, cancelled, attendanceRate }
app.get('/api/teacher/analytics/:studentId', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const studentId = req.params.studentId;
    const ok = await ensureTeacherOwnsStudent(req.userId, studentId);
    if (!ok) return res.status(403).json({ error: 'Not linked to student' });

    const rows = await Attendance.find({ teacherId: req.userId, 'marks.studentId': studentId }).lean();
    let attended = 0, missed = 0;
    for (const r of rows) {
      const rec = (r.marks || []).find((m) => m.studentId?.toString() === studentId);
      if (!rec) continue;
      if (rec.present) attended++; else missed++;
    }
    const cancelled = 0;
    const total = attended + missed;
    const attendanceRate = total > 0 ? attended / total : null;

    return res.json({ attended, missed, cancelled, attendanceRate });
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
