require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();

// Security Middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Config
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'tuitionmanager';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const PORT = parseInt(process.env.PORT, 10) || 3001;

// MongoDB Connection with better options
mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI, { 
  dbName: DB_NAME,
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => console.log('Mongo connected'))
.catch((err) => { 
  console.error('Mongo connect error', err); 
  process.exit(1); 
});

/* ========= Enhanced Schemas & Models ========= */
const { Schema, Types } = mongoose;

// Enhanced User Schema
const UserSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, lowercase: true, unique: true, index: true },
  mobile: { type: String },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['STUDENT', 'TEACHER'], required: true },
  studentCode: { type: String, unique: true, sparse: true, index: true },
  avatar: { type: String },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// Enhanced Teacher-Student Relationship
const TeacherStudentLinkSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
TeacherStudentLinkSchema.index({ teacherId: 1, studentId: 1 }, { unique: true });
const TeacherStudentLink = mongoose.model('TeacherStudentLink', TeacherStudentLinkSchema);

// Enhanced Class Schema
const ClassSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  subject: { type: String, required: true },
  dayOfWeek: { type: Number, required: true },
  startTime: { type: String, required: true },
  endTime: { type: String, required: true },
  colorHex: { type: String },
  notes: { type: String },
  location: { type: String },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User', default: null },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const ClassModel = mongoose.model('Class', ClassSchema);

// Enhanced Assignment Schema
const AssignmentSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  description: { type: String },
  dueAt: { type: String },
  classId: { type: String },
  notes: { type: String },
  priority: { type: Number, default: 0 },
  status: { type: String, enum: ['PENDING', 'IN_PROGRESS', 'COMPLETED', 'OVERDUE'], default: 'PENDING' },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User', default: null },
  attachments: [{
    filename: String,
    originalName: String,
    mimeType: String,
    size: Number,
    url: String,
    uploadedAt: { type: Date, default: Date.now }
  }],
  maxMarks: { type: Number },
  submissionCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Assignment = mongoose.model('Assignment', AssignmentSchema);

// Assignment Submission Schema (NEW)
const AssignmentSubmissionSchema = new Schema({
  assignmentId: { type: Types.ObjectId, ref: 'Assignment', required: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true },
  submittedAt: { type: Date, default: Date.now },
  attachments: [{
    filename: String,
    originalName: String,
    mimeType: String,
    size: Number,
    url: String
  }],
  notes: { type: String },
  marks: { type: Number },
  gradedAt: { type: Date },
  feedback: { type: String },
  status: { type: String, enum: ['SUBMITTED', 'LATE', 'GRADED', 'RETURNED'], default: 'SUBMITTED' }
});
AssignmentSubmissionSchema.index({ assignmentId: 1, studentId: 1 }, { unique: true });
const AssignmentSubmission = mongoose.model('AssignmentSubmission', AssignmentSubmissionSchema);

// Enhanced Note Schema
const NoteSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  content: { type: String },
  subject: { type: String },
  category: { type: String, enum: ['GENERAL', 'LECTURE', 'REFERENCE', 'HOMEWORK', 'OTHER'], default: 'GENERAL' },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User', default: null },
  attachments: [{
    filename: String,
    originalName: String,
    mimeType: String,
    size: Number,
    url: String
  }],
  isPinned: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Note = mongoose.model('Note', NoteSchema);

// Enhanced Exam Schema
const ExamSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  whenAt: { type: String, required: true },
  classId: { type: String },
  location: { type: String },
  notes: { type: String },
  description: { type: String },
  duration: { type: Number, default: 60 },
  instructions: { type: String },
  maxMarks: { type: Number },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User', default: null },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const Exam = mongoose.model('Exam', ExamSchema);

// Enhanced Result Schema
const ResultSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  examId: { type: String, default: null },
  examTitle: { type: String, required: true },
  subject: { type: String, default: null },
  totalMarks: { type: Number, required: true },
  obtainedMarks: { type: Number, required: true },
  percentage: { type: Number },
  grade: { type: String },
  remarks: { type: String, default: null },
  published: { type: Boolean, default: false },
  publishedAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});
const Result = mongoose.model('Result', ResultSchema);

// Enhanced Attendance Schema
const AttendanceSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  classId: { type: String, required: true },
  date: { type: String, required: true },
  session: { type: String, enum: ['MORNING', 'AFTERNOON', 'EVENING'], default: 'MORNING' },
  notes: { type: String },
  marks: [
    {
      studentId: { type: Types.ObjectId, ref: 'User', required: true },
      present: { type: Boolean, required: true },
      joinedAt: { type: Date },
      leftAt: { type: Date }
    }
  ],
  createdAt: { type: Date, default: Date.now }
});
AttendanceSchema.index({ teacherId: 1, classId: 1, date: 1 }, { unique: true });
const Attendance = mongoose.model('Attendance', AttendanceSchema);

// Notification Schema (NEW)
const NotificationSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['ASSIGNMENT', 'EXAM', 'ATTENDANCE', 'RESULT', 'CLASS', 'SYSTEM'], required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  data: { type: Schema.Types.Mixed },
  read: { type: Boolean, default: false },
  readAt: { type: Date },
  priority: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH'], default: 'MEDIUM' },
  expiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', NotificationSchema);

/* ========= Enhanced Helpers ========= */
function nowIso() { return new Date().toISOString(); }
function signToken(user) {
  return jwt.sign({ 
    sub: user._id.toString(), 
    role: user.role, 
    name: user.name,
    email: user.email 
  }, JWT_SECRET, { expiresIn: '30d' });
}
function authRequired(req, res, next) {
  const auth = req.headers.authorization || '';
  const [bearer, token] = auth.split(' ');
  if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    req.role = payload.role;
    req.userEmail = payload.email;
    next();
  } catch { return res.status(401).json({ error: 'Unauthorized' }); }
}

// Role-based middleware
function requireRole(role) {
  return (req, res, next) => {
    if (req.role !== role) {
      return res.status(403).json({ error: `Requires ${role} role` });
    }
    next();
  };
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
  const link = await TeacherStudentLink.findOne({ teacherId, studentId, isActive: true }).lean();
  return !!link;
}

function calculateGrade(percentage) {
  if (percentage >= 90) return 'A+';
  if (percentage >= 80) return 'A';
  if (percentage >= 70) return 'B';
  if (percentage >= 60) return 'C';
  if (percentage >= 50) return 'D';
  return 'F';
}

async function createNotification(userId, type, title, message, data = {}, priority = 'MEDIUM') {
  try {
    await Notification.create({
      userId,
      type,
      title,
      message,
      data,
      priority,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    });
  } catch (error) {
    console.error('Failed to create notification:', error);
  }
}

/* ========= Enhanced Auth Routes ========= */
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
      lastLogin: new Date(),
      createdAt: nowIso()
    });
    const token = signToken(user);

    // Welcome notification
    await createNotification(
      user._id,
      'SYSTEM',
      'Welcome!',
      `Welcome to Tuition Manager! You've successfully registered as a ${role.toLowerCase()}.`
    );

    return res.json({ 
      token, 
      userId: user._id.toString(),
      user: {
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Invalid payload' });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = bcrypt.compareSync(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    const token = signToken(user);
    return res.json({ 
      token, 
      userId: user._id.toString(),
      user: {
        name: user.name,
        email: user.email,
        role: user.role,
        avatar: user.avatar
      }
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Get current user profile
app.get('/api/auth/me', authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-passwordHash').lean();
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        mobile: user.mobile,
        role: user.role,
        avatar: user.avatar,
        studentCode: user.studentCode,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= ALL YOUR EXISTING STUDENT ROUTES ========= */
// GET /api/student/code
app.get('/api/student/code', authRequired, async (req, res) => {
  try {
    if (req.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const user = await User.findById(req.userId);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });

    if (!user.studentCode) {
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
    const rows = await ClassModel.find({
      teacherId: { $in: teacherIds },
      $or: [{ scope: 'ALL' }, { scope: 'INDIVIDUAL', studentId: req.userId }]
    }).sort({ dayOfWeek: 1, startTime: 1 }).lean();
    return res.json(rows.map((r) => ({
      id: r._id.toString(),
      subject: r.subject,
      dayOfWeek: r.dayOfWeek,
      startTime: r.startTime,
      endTime: r.endTime,
      colorHex: r.colorHex || null,
      notes: r.notes || null,
      location: r.location || null
    })));
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
    const rows = await Assignment.find({
      teacherId: { $in: teacherIds },
      $or: [{ scope: 'ALL' }, { scope: 'INDIVIDUAL', studentId: req.userId }]
    }).sort({ dueAt: 1, createdAt: -1 }).lean();
    return res.json(rows.map((r) => ({
      id: r._id.toString(),
      title: r.title,
      dueAt: r.dueAt || null,
      classId: r.classId || null,
      notes: r.notes || null,
      priority: Number.isInteger(r.priority) ? r.priority : 0,
      status: r.status || 'PENDING',
      description: r.description || null,
      attachments: r.attachments || []
    })));
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
    const rows = await Note.find({
      teacherId: { $in: teacherIds },
      $or: [{ scope: 'ALL' }, { scope: 'INDIVIDUAL', studentId: req.userId }]
    }).sort({ createdAt: -1 }).lean();
    return res.json(rows.map((r) => ({
      id: r._id.toString(),
      title: r.title,
      content: r.content || null,
      subject: r.subject || null,
      category: r.category || 'GENERAL',
      attachments: r.attachments || [],
      isPinned: r.isPinned || false
    })));
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
    const rows = await Exam.find({
      teacherId: { $in: teacherIds },
      $or: [{ scope: 'ALL' }, { scope: 'INDIVIDUAL', studentId: req.userId }]
    }).sort({ whenAt: 1 }).lean();
    return res.json(rows.map((r) => ({
      id: r._id.toString(),
      title: r.title,
      whenAt: r.whenAt,
      classId: r.classId || null,
      location: r.location || null,
      notes: r.notes || null,
      description: r.description || null,
      duration: r.duration || 60
    })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/student/results
app.get('/api/student/results', authRequired, async (req, res) => {
  try {
    if (req.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const rows = await Result.find({ studentId: req.userId }).sort({ createdAt: -1 }).lean();
    return res.json(rows.map((r) => ({
      id: r._id.toString(),
      examTitle: r.examTitle,
      subject: r.subject || null,
      totalMarks: r.totalMarks,
      obtainedMarks: r.obtainedMarks,
      percentage: r.percentage,
      grade: r.grade,
      remarks: r.remarks || null,
      published: r.published || false,
      createdAt: r.createdAt?.toISOString?.() || new Date(r.createdAt).toISOString()
    })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= ALL YOUR EXISTING TEACHER ROUTES ========= */
// Teacher: link/list/unlink students
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

    // Notify student
    await createNotification(
      student._id,
      'SYSTEM',
      'Teacher Linked',
      `You've been linked to a new teacher.`,
      { teacherId: req.userId }
    );

    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/teacher/students', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const links = await TeacherStudentLink.find({ teacherId: req.userId })
      .populate('studentId', 'name email mobile studentCode avatar lastLogin')
      .lean();
    const result = links.map((l) => ({
      id: l.studentId._id.toString(),
      name: l.studentId.name,
      email: l.studentId.email,
      mobile: l.studentId.mobile || null,
      code: l.studentId.studentCode || null,
      avatar: l.studentId.avatar || null,
      lastLogin: l.studentId.lastLogin
    }));
    return res.json(result);
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

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

// Teacher: Classes (all your existing class routes remain exactly the same)
app.post('/api/teacher/classes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    let { subject, dayOfWeek, startTime, endTime, colorHex, notes, location, scope, studentId, studentCode } = req.body || {};
    if (!subject || !dayOfWeek || !startTime) return res.status(400).json({ error: 'Invalid payload' });
    if (!endTime) endTime = defaultEndTime(startTime);

    let linkedStudentId = null;
    if (scope === 'INDIVIDUAL') {
      if (!studentId && studentCode) {
        const s = await User.findOne({ studentCode, role: 'STUDENT' }).lean();
        if (!s) return res.status(404).json({ error: 'Student not found' });
        linkedStudentId = s._id;
      } else if (studentId) linkedStudentId = studentId;
      if (linkedStudentId) {
        const ok = await ensureTeacherOwnsStudent(req.userId, linkedStudentId);
        if (!ok) return res.status(403).json({ error: 'Not linked to student' });
      }
    }

    const newClass = await ClassModel.create({
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

    // Notify students about new class
    if (scope === 'ALL') {
      const students = await TeacherStudentLink.find({ teacherId: req.userId }).populate('studentId');
      for (const link of students) {
        await createNotification(
          link.studentId._id,
          'CLASS',
          'New Class Scheduled',
          `New class: ${subject} on day ${dayOfWeek} at ${startTime}`,
          { classId: newClass._id }
        );
      }
    } else if (linkedStudentId) {
      await createNotification(
        linkedStudentId,
        'CLASS',
        'New Individual Class',
        `New individual class: ${subject} on day ${dayOfWeek} at ${startTime}`,
        { classId: newClass._id }
      );
    }

    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// [Include all your existing teacher class routes: GET, GET by id, PUT, DELETE]
app.get('/api/teacher/classes', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await ClassModel.find({ teacherId: req.userId })
      .sort({ dayOfWeek: 1, startTime: 1 }).lean();

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
      studentName: r.studentId ? (nameMap.get(r.studentId.toString()) || null) : null,
      isActive: r.isActive !== false,
      createdAt: r.createdAt?.toISOString?.() || new Date(r.createdAt).toISOString()
    })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/teacher/classes/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const r = await ClassModel.findOne({ _id: req.params.id, teacherId: req.userId }).lean();
    if (!r) return res.status(404).json({ error: 'Not found' });
    return res.json({
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
      isActive: r.isActive !== false,
      createdAt: r.createdAt?.toISOString?.() || new Date(r.createdAt).toISOString()
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/teacher/classes/:id', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const id = req.params.id;
    const body = req.body || {};
    const update = {};
    const keys = ['subject', 'dayOfWeek', 'startTime', 'endTime', 'colorHex', 'notes', 'location', 'scope', 'isActive'];
    for (const k of keys) if (k in body) update[k] = body[k];
    if (update.startTime && !update.endTime) update.endTime = defaultEndTime(update.startTime);

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

// Teacher: Assignments (all your existing assignment routes enhanced)
app.post('/api/teacher/assignments', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const { title, dueAt, classId, notes, priority, scope, studentId, description, maxMarks, attachments } = req.body || {};
    if (!title) return res.status(400).json({ error: 'Title required' });

    if (scope === 'INDIVIDUAL' && studentId) {
      const ok = await ensureTeacherOwnsStudent(req.userId, studentId);
      if (!ok) return res.status(403).json({ error: 'Not linked to student' });
    }

    const assignment = await Assignment.create({
      teacherId: req.userId,
      title,
      description: description || null,
      dueAt: dueAt || null,
      classId: classId || null,
      notes: notes || null,
      priority: Number.isInteger(priority) ? priority : 0,
      scope: scope === 'INDIVIDUAL' ? 'INDIVIDUAL' : 'ALL',
      studentId: scope === 'INDIVIDUAL' ? (studentId || null) : null,
      maxMarks: maxMarks || null,
      attachments: attachments || [],
      createdAt: nowIso()
    });

    // Notify students about new assignment
    if (scope === 'ALL') {
      const students = await TeacherStudentLink.find({ teacherId: req.userId }).populate('studentId');
      for (const link of students) {
        await createNotification(
          link.studentId._id,
          'ASSIGNMENT',
          'New Assignment',
          `New assignment: ${title}`,
          { assignmentId: assignment._id }
        );
      }
    } else if (studentId) {
      await createNotification(
        studentId,
        'ASSIGNMENT',
        'New Individual Assignment',
        `New individual assignment: ${title}`,
        { assignmentId: assignment._id }
      );
    }

    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// [Include all your existing teacher assignment routes: GET, GET by id, PUT, DELETE]
app.get('/api/teacher/assignments', authRequired, async (req, res) => {
  try {
    if (req.role !== 'TEACHER') return res.status(403).json({ error: 'Forbidden' });
    const rows = await Assignment.find({ teacherId: req.userId }).sort({ createdAt: -1 }).lean();
    return res.json(rows.map((r) => ({
      id: r._id.toString(),
      title: r.title,
      description: r.description || null,
      dueAt: r.dueAt || null,
      classId: r.classId || null,
      notes: r.notes || null,
      priority: Number.isInteger(r.priority) ? r.priority : 0,
      status: r.status || 'PENDING',
      scope: r.scope || 'ALL',
      studentId: r.studentId ? r.studentId.toString() : null,
      maxMarks: r.maxMarks || null,
      submissionCount: r.submissionCount || 0,
      attachments: r.attachments || [],
      createdAt: r.createdAt?.toISOString?.() || new Date(r.createdAt).toISOString(),
      updatedAt: r.updatedAt?.toISOString?.() || new Date(r.updatedAt).toISOString()
    })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// [Include all your existing teacher notes routes]
// [Include all your existing teacher exams routes] 
// [Include all your existing teacher results routes]
// [Include all your existing attendance routes]

/* ========= NEW: Assignment Submission Routes ========= */
app.post('/api/student/assignments/:id/submit', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const assignmentId = req.params.id;
    const { notes, attachments } = req.body || {};

    const assignment = await Assignment.findById(assignmentId);
    if (!assignment) return res.status(404).json({ error: 'Assignment not found' });

    // Check if student is linked to teacher
    const link = await TeacherStudentLink.findOne({
      studentId: req.userId,
      teacherId: assignment.teacherId
    });
    if (!link) return res.status(403).json({ error: 'Not authorized to submit this assignment' });

    // Create or update submission
    const submission = await AssignmentSubmission.findOneAndUpdate(
      { assignmentId, studentId: req.userId },
      {
        notes: notes || '',
        attachments: attachments || [],
        submittedAt: new Date(),
        status: new Date() > new Date(assignment.dueAt) ? 'LATE' : 'SUBMITTED'
      },
      { upsert: true, new: true }
    );

    // Update assignment submission count
    await Assignment.findByIdAndUpdate(assignmentId, {
      $inc: { submissionCount: 1 }
    });

    // Notify teacher
    const student = await User.findById(req.userId);
    await createNotification(
      assignment.teacherId,
      'ASSIGNMENT',
      'New Assignment Submission',
      `${student.name} submitted assignment: ${assignment.title}`,
      { assignmentId, studentId: req.userId, submissionId: submission._id },
      'MEDIUM'
    );

    res.status(201).json({ 
      message: 'Assignment submitted successfully',
      submissionId: submission._id
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Get assignment submissions for teacher
app.get('/api/teacher/assignments/:id/submissions', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const assignmentId = req.params.id;
    
    // Verify assignment belongs to teacher
    const assignment = await Assignment.findOne({ _id: assignmentId, teacherId: req.userId });
    if (!assignment) return res.status(404).json({ error: 'Assignment not found' });

    const submissions = await AssignmentSubmission.find({ assignmentId })
      .populate('studentId', 'name email studentCode avatar')
      .sort({ submittedAt: -1 })
      .lean();

    return res.json(submissions.map(s => ({
      id: s._id.toString(),
      student: {
        id: s.studentId._id.toString(),
        name: s.studentId.name,
        email: s.studentId.email,
        studentCode: s.studentId.studentCode,
        avatar: s.studentId.avatar
      },
      submittedAt: s.submittedAt,
      notes: s.notes,
      attachments: s.attachments,
      marks: s.marks,
      feedback: s.feedback,
      status: s.status,
      gradedAt: s.gradedAt
    })));
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Grade assignment submission
app.put('/api/teacher/submissions/:id/grade', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const submissionId = req.params.id;
    const { marks, feedback } = req.body || {};

    const submission = await AssignmentSubmission.findById(submissionId).populate('assignmentId');
    if (!submission) return res.status(404).json({ error: 'Submission not found' });

    // Verify teacher owns the assignment
    if (submission.assignmentId.teacherId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const updateData = {
      marks: marks !== undefined ? marks : submission.marks,
      feedback: feedback || submission.feedback,
      gradedAt: new Date(),
      status: 'GRADED'
    };

    await AssignmentSubmission.findByIdAndUpdate(submissionId, updateData);

    // Notify student
    await createNotification(
      submission.studentId,
      'ASSIGNMENT',
      'Assignment Graded',
      `Your assignment "${submission.assignmentId.title}" has been graded.`,
      { assignmentId: submission.assignmentId._id, submissionId: submission._id },
      'MEDIUM'
    );

    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= NEW: Notification Routes ========= */
app.get('/api/notifications', authRequired, async (req, res) => {
  try {
    const { page = 1, limit = 20, unreadOnly } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const query = { userId: req.userId };
    if (unreadOnly === 'true') {
      query.read = false;
    }

    const notifications = await Notification.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await Notification.countDocuments(query);
    const unreadCount = await Notification.countDocuments({ 
      userId: req.userId, 
      read: false 
    });

    res.json({
      notifications: notifications.map(n => ({
        id: n._id.toString(),
        type: n.type,
        title: n.title,
        message: n.message,
        data: n.data,
        read: n.read,
        priority: n.priority,
        createdAt: n.createdAt
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      },
      unreadCount
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/notifications/:id/read', authRequired, async (req, res) => {
  try {
    await Notification.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { 
        read: true,
        readAt: new Date()
      }
    );
    res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/notifications/read-all', authRequired, async (req, res) => {
  try {
    await Notification.updateMany(
      { userId: req.userId, read: false },
      { 
        read: true,
        readAt: new Date()
      }
    );
    res.status(204).send();
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Enhanced Analytics ========= */
app.get('/api/teacher/analytics/overview', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;

    // Get student count
    const studentCount = await TeacherStudentLink.countDocuments({ 
      teacherId, 
      isActive: true 
    });

    // Get class count
    const classCount = await ClassModel.countDocuments({ 
      teacherId, 
      isActive: true 
    });

    // Get pending assignments
    const pendingAssignments = await Assignment.countDocuments({
      teacherId,
      status: { $in: ['PENDING', 'IN_PROGRESS'] }
    });

    // Get upcoming exams (next 7 days)
    const upcomingExams = await Exam.countDocuments({
      teacherId,
      whenAt: { $gte: new Date().toISOString().split('T')[0], $lte: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] },
      isActive: true
    });

    // Get total submissions
    const teacherAssignments = await Assignment.find({ teacherId }).select('_id');
    const assignmentIds = teacherAssignments.map(a => a._id);
    const totalSubmissions = await AssignmentSubmission.countDocuments({
      assignmentId: { $in: assignmentIds }
    });

    res.json({
      studentCount,
      classCount,
      pendingAssignments,
      upcomingExams,
      totalSubmissions
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Enhanced student analytics
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
    const total = attended + missed;
    const attendanceRate = total > 0 ? (attended / total) * 100 : 0;

    // Get assignment statistics
    const teacherAssignments = await Assignment.find({ teacherId: req.userId }).select('_id');
    const assignmentIds = teacherAssignments.map(a => a._id);
    const submissions = await AssignmentSubmission.find({
      studentId,
      assignmentId: { $in: assignmentIds }
    });

    const gradedSubmissions = submissions.filter(s => s.status === 'GRADED');
    const averageMarks = gradedSubmissions.length > 0 
      ? gradedSubmissions.reduce((sum, s) => sum + (s.marks || 0), 0) / gradedSubmissions.length 
      : 0;

    // Get results statistics
    const results = await Result.find({ studentId, teacherId: req.userId });
    const averagePercentage = results.length > 0
      ? results.reduce((sum, r) => sum + ((r.obtainedMarks / r.totalMarks) * 100), 0) / results.length
      : 0;

    return res.json({ 
      attendance: {
        attended, 
        missed, 
        total,
        attendanceRate: Math.round(attendanceRate)
      },
      assignments: {
        total: submissions.length,
        submitted: submissions.filter(s => ['SUBMITTED', 'LATE', 'GRADED'].includes(s.status)).length,
        graded: gradedSubmissions.length,
        averageMarks: Math.round(averageMarks * 100) / 100
      },
      performance: {
        totalExams: results.length,
        averagePercentage: Math.round(averagePercentage * 100) / 100
      }
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ========= Health Check ========= */
app.get('/health', async (_req, res) => {
  try {
    // Check database connection
    await mongoose.connection.db.admin().ping();
    res.json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: 'Connected'
    });
  } catch (error) {
    res.status(503).json({ 
      status: 'Service Unavailable', 
      timestamp: new Date().toISOString(),
      database: 'Disconnected'
    });
  }
});

/* ========= Fallback ========= */
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// Global Error Handler
app.use((error, _req, res, _next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server listening on :${PORT}`);
});
