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
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// ========= FIX: Trust proxy for Render.com =========
app.set('trust proxy', 1);

// ========= SECURITY & MIDDLEWARE =========
app.use(helmet());
app.use(mongoSanitize());
app.use(cors({
  origin: "*",
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('combined'));

// ========= FIX: Rate limiting with proxy fix =========
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP' },
  trustProxy: 1
});
app.use('/api/', limiter);

// ========= CONFIG =========
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/tuitionmanager';
const JWT_SECRET = process.env.JWT_SECRET || 'mobile_app_secret_key_2024';
const PORT = process.env.PORT || 3001;

// ========= MONGODB CONNECTION =========
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ MongoDB connected successfully');
  console.log('🗄️ Database:', mongoose.connection.name);
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// This event will fire when the database is ready
mongoose.connection.on('open', function() {
  console.log('🎯 Database is ready for operations');
});

// ========= ENHANCED SCHEMAS =========
const { Schema, Types } = mongoose;

// User Schema
const UserSchema = new Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, lowercase: true, unique: true },
  mobile: { type: String, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['STUDENT', 'TEACHER'], required: true },
  studentCode: { type: String, unique: true, sparse: true },
  avatar: { type: String },
  fcmToken: { type: String },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

// Teacher-Student Link - UPDATED WITH SOFT DELETE
const TeacherStudentLinkSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true },
  isActive: { type: Boolean, default: true },
  linkedAt: { type: Date, default: Date.now },
  unlinkedAt: { type: Date }
});
TeacherStudentLinkSchema.index({ teacherId: 1, studentId: 1 }, { unique: true });

// Class Schema
const ClassSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  subject: { type: String, required: true },
  title: { type: String, required: true },
  dayOfWeek: { type: Number, required: true, min: 1, max: 7 },
  startTime: { type: String, required: true },
  endTime: { type: String, required: true },
  colorHex: { type: String, default: '#3B82F6' },
  notes: { type: String },
  location: { type: String },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// Assignment Schema
const AssignmentSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String },
  dueAt: { type: Date, required: true },
  classId: { type: String },
  notes: { type: String },
  priority: { type: Number, enum: [0, 1, 2], default: 1 }, // 0=LOW, 1=MEDIUM, 2=HIGH
  status: { type: String, enum: ['PENDING', 'IN_PROGRESS', 'COMPLETED', 'OVERDUE'], default: 'PENDING' },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User' },
  attachments: [{
    filename: String,
    url: String,
    type: String,
    size: Number,
    uploadedAt: { type: Date, default: Date.now }
  }],
  maxMarks: { type: Number },
  submissionCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Assignment Submission
const AssignmentSubmissionSchema = new Schema({
  assignmentId: { type: Types.ObjectId, ref: 'Assignment', required: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true },
  submittedAt: { type: Date, default: Date.now },
  attachments: [{
    filename: String,
    url: String,
    type: String,
    size: Number
  }],
  notes: { type: String },
  marks: { type: Number },
  feedback: { type: String },
  status: { type: String, enum: ['SUBMITTED', 'LATE', 'GRADED', 'RETURNED'], default: 'SUBMITTED' },
  gradedAt: { type: Date }
});
AssignmentSubmissionSchema.index({ assignmentId: 1, studentId: 1 }, { unique: true });

// Note Schema
const NoteSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  content: { type: String },
  subject: { type: String },
  category: { type: String, enum: ['GENERAL', 'LECTURE', 'REFERENCE', 'HOMEWORK'], default: 'GENERAL' },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User' },
  isPinned: { type: Boolean, default: false },
  attachments: [{
    filename: String,
    url: String,
    type: String,
    size: Number
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Exam Schema
const ExamSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String },
  whenAt: { type: Date, required: true },
  classId: { type: String },
  location: { type: String },
  notes: { type: String },
  maxMarks: { type: Number, required: true },
  duration: { type: Number, default: 60 },
  scope: { type: String, enum: ['ALL', 'INDIVIDUAL'], default: 'ALL' },
  studentId: { type: Types.ObjectId, ref: 'User' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// Result Schema
const ResultSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true },
  examId: { type: Types.ObjectId, ref: 'Exam' },
  examTitle: { type: String, required: true },
  subject: { type: String, required: true },
  totalMarks: { type: Number, required: true },
  obtainedMarks: { type: Number, required: true },
  percentage: { type: Number },
  grade: { type: String },
  remarks: { type: String },
  published: { type: Boolean, default: false },
  publishedAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

// Attendance Schema
const AttendanceSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  classId: { type: String, required: true },
  date: { type: String, required: true },
  marks: [{
    studentId: { type: Types.ObjectId, ref: 'User', required: true },
    present: { type: Boolean, required: true },
    joinedAt: { type: Date },
    leftAt: { type: Date }
  }],
  createdAt: { type: Date, default: Date.now }
});
AttendanceSchema.index({ teacherId: 1, classId: 1, date: 1 }, { unique: true });

// Notification Schema
const NotificationSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['ASSIGNMENT', 'EXAM', 'ATTENDANCE', 'RESULT', 'CLASS', 'SYSTEM'], required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  data: { type: Schema.Types.Mixed },
  read: { type: Boolean, default: false },
  readAt: { type: Date },
  priority: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH'], default: 'MEDIUM' },
  createdAt: { type: Date, default: Date.now }
});

// Planner/Task Schema - Add this after the Notification Schema
const PlannerTaskSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String },
  date: { type: Date, required: true },
  startTime: { type: String }, // "09:00"
  endTime: { type: String }, // "10:00"
  type: { type: String, enum: ['STUDY', 'CLASS', 'EXERCISE', 'WORK', 'PERSONAL', 'OTHER'], default: 'STUDY' },
  location: { type: String },
  priority: { type: Number, enum: [0, 1, 2], default: 1 }, // 0=LOW, 1=MEDIUM, 2=HIGH
  completed: { type: Boolean, default: false },
  completedAt: { type: Date },
  notifyBefore: { type: Number, default: 30 }, // Minutes before to notify
  repeatType: { type: String, enum: ['NONE', 'DAILY', 'WEEKLY', 'MONTHLY'], default: 'NONE' },
  repeatUntil: { type: Date },
  colorHex: { type: String, default: '#3B82F6' },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const PlannerTask = mongoose.model('PlannerTask', PlannerTaskSchema);

// ========= MODELS =========
const User = mongoose.model('User', UserSchema);
const TeacherStudentLink = mongoose.model('TeacherStudentLink', TeacherStudentLinkSchema);
const ClassModel = mongoose.model('Class', ClassSchema);
const Assignment = mongoose.model('Assignment', AssignmentSchema);
const AssignmentSubmission = mongoose.model('AssignmentSubmission', AssignmentSubmissionSchema);
const Note = mongoose.model('Note', NoteSchema);
const Exam = mongoose.model('Exam', ExamSchema);
const Result = mongoose.model('Result', ResultSchema);
const Attendance = mongoose.model('Attendance', AttendanceSchema);
const Notification = mongoose.model('Notification', NotificationSchema);

// ========= HELPER FUNCTIONS =========
const generateStudentCode = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
};

const calculateGrade = (percentage) => {
  if (percentage >= 90) return 'A+';
  if (percentage >= 80) return 'A';
  if (percentage >= 70) return 'B';
  if (percentage >= 60) return 'C';
  if (percentage >= 50) return 'D';
  return 'F';
};

const ensureTeacherOwnsStudent = async (teacherId, studentId) => {
  const link = await TeacherStudentLink.findOne({ teacherId, studentId, isActive: true });
  return !!link;
};

// Helper function to get linked teacher IDs for a student
const getLinkedTeacherIds = async (studentId) => {
  const links = await TeacherStudentLink.find({ 
    studentId, 
    isActive: true 
  }).select('teacherId');
  return links.map(link => link.teacherId);
};

const createNotification = async (userId, type, title, message, data = {}) => {
  try {
    const notification = await Notification.create({
      userId,
      type,
      title,
      message,
      data,
      createdAt: new Date()
    });
    
    // Emit real-time notification
    io.to(userId.toString()).emit('new_notification', notification);
    
    return notification;
  } catch (error) {
    console.error('Notification creation error:', error);
  }
};

// ========= AUTH MIDDLEWARE =========
const authRequired = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    req.userId = decoded.sub;
    req.role = decoded.role;
    req.userEmail = decoded.email;
    
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const requireRole = (role) => (req, res, next) => {
  if (req.role !== role) {
    return res.status(403).json({ error: `Access denied. Requires ${role} role.` });
  }
  next();
};

// ========= SOCKET.IO FOR REAL-TIME =========
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join_user', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined their room`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// ========= ROOT & HEALTH ENDPOINTS =========
app.get('/', (req, res) => {
  res.json({ 
    message: 'Tuition Manager Backend API',
    status: 'Running',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Tuition Manager API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    database: 'Connected'
  });
});

// ============================================
// TEACHER-STUDENT LINK ENDPOINTS - UPDATED ✅
// ============================================

// POST /api/teacher/link-student - Link a student using their code
// SUPPORTS: Multiple teachers linking the same student ✅
app.post('/api/teacher/link-student', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Student code is required' });
    }

    // Find student by code
    const student = await User.findOne({ 
      studentCode: code, 
      role: 'STUDENT', 
      isActive: true 
    });

    if (!student) {
      return res.status(404).json({ error: 'Student not found with this code' });
    }

    // Check if THIS teacher already linked THIS student
    const existingLink = await TeacherStudentLink.findOne({
      teacherId: req.userId,
      studentId: student._id,
      isActive: true
    });

    if (existingLink) {
      // Already linked by THIS teacher
      return res.status(200).json({ 
        success: true, 
        message: 'Student is already linked to your account' 
      });
    }

    // Check if link existed before but was deactivated
    const deactivatedLink = await TeacherStudentLink.findOne({
      teacherId: req.userId,
      studentId: student._id,
      isActive: false
    });

    if (deactivatedLink) {
      // Reactivate the link
      deactivatedLink.isActive = true;
      deactivatedLink.linkedAt = new Date();
      await deactivatedLink.save();
    } else {
      // Create new link - ALLOWS MULTIPLE TEACHERS PER STUDENT ✅
      await TeacherStudentLink.create({
        teacherId: req.userId,
        studentId: student._id,
        isActive: true,
        linkedAt: new Date()
      });
    }

    // Send notification to student
    const teacher = await User.findById(req.userId);
    await createNotification(
      student._id,
      'SYSTEM',
      'New Teacher Connection',
      `${teacher.name} has linked you as their student`,
      { teacherId: req.userId }
    );

    // Count how many teachers this student has
    const linkCount = await TeacherStudentLink.countDocuments({
      studentId: student._id,
      isActive: true
    });

    console.log(`✅ Teacher ${teacher.email} linked student ${student.email} (Student now has ${linkCount} teachers)`);

    res.status(200).json({ 
      success: true, 
      message: `Successfully linked ${student.name}` 
    });
  } catch (error) {
    console.error('Link student error:', error);
    res.status(500).json({ error: 'Failed to link student' });
  }
});

// GET /api/teacher/students - List all students linked to this teacher
app.get('/api/teacher/students', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;

    // Get all active links for this teacher
    const links = await TeacherStudentLink.find({ 
      teacherId, 
      isActive: true 
    }).populate('studentId', 'name email mobile studentCode');

    // Format the response
    const students = links
      .filter(link => link.studentId) // Filter out any null references
      .map(link => ({
        id: link.studentId._id.toString(),
        name: link.studentId.name,
        email: link.studentId.email,
        mobile: link.studentId.mobile,
        code: link.studentId.studentCode
      }));

    res.json({ success: true, students });
  } catch (error) {
    console.error('List students error:', error);
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

// DELETE /api/teacher/students/:id - Unlink a student from this teacher
app.delete('/api/teacher/students/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const studentId = req.params.id;
    const teacherId = req.userId;

    // Find and deactivate the link (soft delete)
    const result = await TeacherStudentLink.findOneAndUpdate(
      { teacherId, studentId, isActive: true },
      { isActive: false, unlinkedAt: new Date() },
      { new: true }
    );

    if (!result) {
      return res.status(404).json({ error: 'Student link not found' });
    }

    // Notify student
    const teacher = await User.findById(teacherId);
    await createNotification(
      studentId,
      'SYSTEM',
      'Teacher Disconnected',
      `${teacher.name} has removed you from their student list`,
      { teacherId }
    );

    console.log(`✅ Teacher ${teacher.email} unlinked student ${studentId}`);

    res.status(204).send(); // No content
  } catch (error) {
    console.error('Unlink student error:', error);
    res.status(500).json({ error: 'Failed to unlink student' });
  }
});

// ============================================
// STUDENT ENDPOINTS - Scoped to Linked Teachers ONLY
// ============================================

// GET /api/student/classes - Only classes from linked teachers
// GET /api/student/classes - Only classes from linked teachers
app.get('/api/student/classes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, classes: [] });
    }
    
    const classes = await ClassModel.find({
      teacherId: { $in: linkedTeacherIds },
      isActive: true,
      $or: [
        { scope: 'ALL' },
        { scope: { $exists: false } },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    })
    .populate('teacherId', 'name')  // ✅ ADD THIS
    .sort({ dayOfWeek: 1, startTime: 1 })
    .lean();
    
    const formatted = classes.map(c => ({
      id: c._id.toString(),
      subject: c.subject || c.title,
      dayOfWeek: c.dayOfWeek,
      startTime: c.startTime,
      endTime: c.endTime,
      colorHex: c.colorHex,
      notes: c.notes,
      location: c.location,
      teacherName: c.teacherId?.name  // ✅ ADD THIS
    }));
    
    res.json({ success: true, classes: formatted });
  } catch (error) {
    console.error('Student classes error:', error);
    res.status(500).json({ error: 'Failed to fetch classes' });
  }
});

// GET /api/student/assignments - Only assignments from linked teachers
app.get('/api/student/assignments', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, assignments: [] });
    }
    
    const assignments = await Assignment.find({
      teacherId: { $in: linkedTeacherIds },
      $or: [
        { scope: 'ALL' },
        { scope: { $exists: false } },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    }).lean();
    
    const formatted = assignments.map(a => ({
      id: a._id.toString(),
      title: a.title,
      dueAt: a.dueAt ? a.dueAt.toISOString() : null,
      classId: a.classId ? a.classId.toString() : null,
      notes: a.notes,
      priority: a.priority || 0
    }));
    
    res.json({ success: true, assignments: formatted });
  } catch (error) {
    console.error('Student assignments error:', error);
    res.status(500).json({ error: 'Failed to fetch assignments' });
  }
});

// GET /api/student/notes - Only notes from linked teachers
app.get('/api/student/notes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, notes: [] });
    }
    
    const notes = await Note.find({
      teacherId: { $in: linkedTeacherIds },
      $or: [
        { scope: 'ALL' },
        { scope: { $exists: false } },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    }).lean();
    
    const formatted = notes.map(n => ({
      id: n._id.toString(),
      title: n.title,
      content: n.content,
      subject: n.subject
    }));
    
    res.json({ success: true, notes: formatted });
  } catch (error) {
    console.error('Student notes error:', error);
    res.status(500).json({ error: 'Failed to fetch notes' });
  }
});

// GET /api/student/exams - Only exams from linked teachers
app.get('/api/student/exams', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, exams: [] });
    }
    
    const exams = await Exam.find({
      teacherId: { $in: linkedTeacherIds },
      isActive: true,
      $or: [
        { scope: 'ALL' },
        { scope: { $exists: false } },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    }).lean();
    
    const formatted = exams.map(e => ({
      id: e._id.toString(),
      title: e.title,
      whenAt: e.whenAt.toISOString(),
      classId: e.classId ? e.classId.toString() : null,
      location: e.location,
      notes: e.notes
    }));
    
    res.json({ success: true, exams: formatted });
  } catch (error) {
    console.error('Student exams error:', error);
    res.status(500).json({ error: 'Failed to fetch exams' });
  }
});

// GET /api/student/results - Only results from linked teachers
app.get('/api/student/results', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, results: [] });
    }
    
    // Results should be specifically for this student
    const results = await Result.find({
      teacherId: { $in: linkedTeacherIds },
      studentId: studentId
    }).lean();
    
    const formatted = results.map(r => ({
      id: r._id.toString(),
      examTitle: r.examTitle,
      subject: r.subject,
      totalMarks: r.totalMarks,
      obtainedMarks: r.obtainedMarks,
      remarks: r.remarks,
      createdAt: r.createdAt.toISOString()
    }));
    
    res.json({ success: true, results: formatted });
  } catch (error) {
    console.error('Student results error:', error);
    res.status(500).json({ error: 'Failed to fetch results' });
  }
});

// ========= AUTH ROUTES =========
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, mobile } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!['STUDENT', 'TEACHER'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = bcrypt.hashSync(password, 12);
    const userData = {
      name: name.trim(),
      email: email.toLowerCase().trim(),
      passwordHash,
      role,
      mobile: mobile?.trim() || null,
      lastLogin: new Date()
    };

    if (role === 'STUDENT') {
      let studentCode;
      do {
        studentCode = generateStudentCode();
      } while (await User.findOne({ studentCode }));
      userData.studentCode = studentCode;
    }

    const user = await User.create(userData);

    const token = jwt.sign(
      { 
        sub: user._id.toString(), 
        role: user.role, 
        name: user.name,
        email: user.email 
      }, 
      JWT_SECRET, 
      { expiresIn: '30d' }
    );

    await createNotification(
      user._id,
      'SYSTEM',
      'Welcome to Tuition Manager!',
      `You have successfully registered as a ${role.toLowerCase()}.`,
      { userId: user._id }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        mobile: user.mobile,
        studentCode: user.studentCode,
        avatar: user.avatar
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = bcrypt.compareSync(password, user.passwordHash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { 
        sub: user._id.toString(), 
        role: user.role, 
        name: user.name,
        email: user.email 
      }, 
      JWT_SECRET, 
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        mobile: user.mobile,
        studentCode: user.studentCode,
        avatar: user.avatar,
        lastLogin: user.lastLogin
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

app.get('/api/auth/me', authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-passwordHash');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        mobile: user.mobile,
        studentCode: user.studentCode,
        avatar: user.avatar,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ========= DELETE ACCOUNT =========
app.delete('/api/auth/account', authRequired, async (req, res) => {
  try {
    const userId = req.userId;
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const role = user.role;

    if (role === 'TEACHER') {
      // Delete teacher-specific data
      // 1. Remove all teacher-student links
      await TeacherStudentLink.deleteMany({ teacherId: userId });
      
      // 2. Delete all classes created by teacher
      await ClassModel.deleteMany({ teacherId: userId });
      
      // 3. Delete all assignments created by teacher
      const teacherAssignments = await Assignment.find({ teacherId: userId });
      const assignmentIds = teacherAssignments.map(a => a._id);
      await AssignmentSubmission.deleteMany({ assignmentId: { $in: assignmentIds } });
      await Assignment.deleteMany({ teacherId: userId });
      
      // 4. Delete all notes created by teacher
      await Note.deleteMany({ teacherId: userId });
      
      // 5. Delete all exams created by teacher
      await Exam.deleteMany({ teacherId: userId });
      
      // 6. Delete all results created by teacher
      await Result.deleteMany({ teacherId: userId });
      
      // 7. Delete all attendance records
      await Attendance.deleteMany({ teacherId: userId });
      
    } else if (role === 'STUDENT') {
      // Delete student-specific data
      // 1. Remove from all teacher-student links
      await TeacherStudentLink.deleteMany({ studentId: userId });
      
      // 2. Delete all assignment submissions by this student
      await AssignmentSubmission.deleteMany({ studentId: userId });
      
      // 3. Delete results for this student
      await Result.deleteMany({ studentId: userId });
      
      // 4. Remove student from attendance records
      await Attendance.updateMany(
        {},
        { $pull: { marks: { studentId: userId } } }
      );
    }

    // Delete all notifications for this user
    await Notification.deleteMany({ userId });

    // Finally, delete the user account
    await User.findByIdAndDelete(userId);

    // Log the deletion
    console.log(`✅ Account deleted: ${user.email} (${role})`);

    res.status(204).send(); // No Content - successful deletion
  } catch (error) {
    console.error('Account deletion error:', error);
    res.status(500).json({ error: 'Failed to delete account. Please try again.' });
  }
});

// ========= STUDENT ROUTES - SCOPED TO LINKED TEACHERS ONLY =========

// 1. GET /api/student/code - Get Student Code
app.get('/api/student/code', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('studentCode');
    if (!user || !user.studentCode) {
      return res.status(404).json({ error: 'Student code not found' });
    }
    res.json({ success: true, code: user.studentCode });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch student code' });
  }
});

app.get('/api/student/profile', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-passwordHash');
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.get('/api/student/teachers', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const links = await TeacherStudentLink.find({ studentId: req.userId, isActive: true })
      .populate('teacherId', 'name email mobile avatar')
      .lean();

    const teachers = links.map(link => ({
      id: link.teacherId._id.toString(),
      name: link.teacherId.name,
      email: link.teacherId.email,
      mobile: link.teacherId.mobile,
      avatar: link.teacherId.avatar
    }));

    res.json({ success: true, teachers });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch teachers' });
  }
});

// Enhanced student classes endpoint with teacher info
app.get('/api/student/classes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    
    // Get all teacher IDs that have linked this student
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      // Student not linked to any teacher yet
      return res.json({ success: true, classes: [] });
    }
    
    // Fetch classes from linked teachers only
    // Classes with scope="ALL" or scope="INDIVIDUAL" where studentId matches
    const classes = await ClassModel.find({
      teacherId: { $in: linkedTeacherIds },
      isActive: true,
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ dayOfWeek: 1, startTime: 1 })
    .lean();
    
    const formatted = classes.map(c => ({
      id: c._id.toString(),
      subject: c.subject || c.title,
      title: c.title,
      dayOfWeek: c.dayOfWeek,
      startTime: c.startTime,
      endTime: c.endTime,
      colorHex: c.colorHex,
      notes: c.notes,
      location: c.location,
      teacherName: c.teacherId?.name,
      scope: c.scope
    }));
    
    res.json({ success: true, classes: formatted });
  } catch (error) {
    console.error('Student classes error:', error);
    res.status(500).json({ error: 'Failed to fetch classes' });
  }
});

// Enhanced student assignments endpoint with submission status
app.get('/api/student/assignments', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, assignments: [] });
    }
    
    const assignments = await Assignment.find({
      teacherId: { $in: linkedTeacherIds },
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ dueAt: 1 })
    .lean();
    
    // Check submission status for each assignment
    const assignmentsWithStatus = await Promise.all(
      assignments.map(async (assignment) => {
        const submission = await AssignmentSubmission.findOne({
          assignmentId: assignment._id,
          studentId: studentId
        });

        return {
          id: assignment._id.toString(),
          title: assignment.title,
          description: assignment.description,
          dueAt: assignment.dueAt,
          priority: assignment.priority,
          status: assignment.status,
          teacherName: assignment.teacherId.name,
          submissionStatus: submission ? submission.status : 'NOT_SUBMITTED',
          submittedAt: submission?.submittedAt,
          marks: submission?.marks,
          attachments: assignment.attachments || []
        };
      })
    );
    
    res.json({ success: true, assignments: assignmentsWithStatus });
  } catch (error) {
    console.error('Student assignments error:', error);
    res.status(500).json({ error: 'Failed to fetch assignments' });
  }
});

// Enhanced student notes endpoint
app.get('/api/student/notes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, notes: [] });
    }
    
    const notes = await Note.find({
      teacherId: { $in: linkedTeacherIds },
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ createdAt: -1 })
    .lean();
    
    const formatted = notes.map(n => ({
      id: n._id.toString(),
      title: n.title,
      content: n.content,
      subject: n.subject,
      teacherName: n.teacherId?.name,
      isPinned: n.isPinned,
      attachments: n.attachments || [],
      createdAt: n.createdAt
    }));
    
    res.json({ success: true, notes: formatted });
  } catch (error) {
    console.error('Student notes error:', error);
    res.status(500).json({ error: 'Failed to fetch notes' });
  }
});

// Enhanced student exams endpoint
app.get('/api/student/exams', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, exams: [] });
    }
    
    const exams = await Exam.find({
      teacherId: { $in: linkedTeacherIds },
      isActive: true,
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ whenAt: 1 })
    .lean();
    
    const formatted = exams.map(e => ({
      id: e._id.toString(),
      title: e.title,
      description: e.description,
      whenAt: e.whenAt.toISOString(),
      location: e.location,
      duration: e.duration,
      maxMarks: e.maxMarks,
      teacherName: e.teacherId.name,
      notes: e.notes
    }));
    
    res.json({ success: true, exams: formatted });
  } catch (error) {
    console.error('Student exams error:', error);
    res.status(500).json({ error: 'Failed to fetch exams' });
  }
});

// Enhanced student results endpoint
app.get('/api/student/results', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, results: [] });
    }
    
    // Results should be specifically for this student
    const results = await Result.find({
      teacherId: { $in: linkedTeacherIds },
      studentId: studentId,
      published: true
    })
    .populate('teacherId', 'name')
    .sort({ createdAt: -1 })
    .lean();
    
    const formatted = results.map(r => {
      const percentage = (r.obtainedMarks / r.totalMarks) * 100;
      return {
        id: r._id.toString(),
        examTitle: r.examTitle,
        subject: r.subject,
        totalMarks: r.totalMarks,
        obtainedMarks: r.obtainedMarks,
        percentage: Math.round(percentage * 100) / 100,
        grade: r.grade || calculateGrade(percentage),
        remarks: r.remarks,
        teacherName: r.teacherId.name,
        publishedAt: r.publishedAt,
        createdAt: r.createdAt.toISOString()
      };
    });
    
    res.json({ success: true, results: formatted });
  } catch (error) {
    console.error('Student results error:', error);
    res.status(500).json({ error: 'Failed to fetch results' });
  }
});

app.get('/api/student/dashboard', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ 
        success: true, 
        dashboard: {
          todayClasses: [],
          upcomingAssignments: [],
          recentNotifications: []
        }
      });
    }

    // Today's classes
    const today = new Date();
    const dayOfWeek = today.getDay() || 7;
    const todayClasses = await ClassModel.find({
      teacherId: { $in: linkedTeacherIds },
      dayOfWeek: dayOfWeek,
      isActive: true,
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ startTime: 1 })
    .lean();

    // Upcoming assignments (next 7 days)
    const nextWeek = new Date();
    nextWeek.setDate(nextWeek.getDate() + 7);
    
    const upcomingAssignments = await Assignment.find({
      teacherId: { $in: linkedTeacherIds },
      dueAt: { $gte: today, $lte: nextWeek },
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: studentId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ dueAt: 1 })
    .limit(5)
    .lean();

    // Recent notifications
    const recentNotifications = await Notification.find({ userId: studentId })
      .sort({ createdAt: -1 })
      .limit(5)
      .lean();

    res.json({
      success: true,
      dashboard: {
        todayClasses: todayClasses.map(cls => ({
          id: cls._id.toString(),
          subject: cls.subject,
          title: cls.title,
          startTime: cls.startTime,
          endTime: cls.endTime,
          teacherName: cls.teacherId.name,
          location: cls.location
        })),
        upcomingAssignments: upcomingAssignments.map(assignment => ({
          id: assignment._id.toString(),
          title: assignment.title,
          dueAt: assignment.dueAt,
          priority: assignment.priority,
          teacherName: assignment.teacherId.name
        })),
        recentNotifications: recentNotifications.map(notif => ({
          id: notif._id.toString(),
          title: notif.title,
          message: notif.message,
          type: notif.type,
          read: notif.read,
          createdAt: notif.createdAt
        }))
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// ========= TEACHER ROUTES =========

app.get('/api/teacher/dashboard', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;

    // Basic counts
    const studentCount = await TeacherStudentLink.countDocuments({ teacherId, isActive: true });
    const classCount = await ClassModel.countDocuments({ teacherId, isActive: true });
    const assignmentCount = await Assignment.countDocuments({ teacherId });
    const examCount = await Exam.countDocuments({ teacherId, isActive: true });

    // Pending submissions
    const assignments = await Assignment.find({ teacherId }).select('_id');
    const assignmentIds = assignments.map(a => a._id);
    const pendingSubmissions = await AssignmentSubmission.countDocuments({
      assignmentId: { $in: assignmentIds },
      status: { $in: ['SUBMITTED', 'LATE'] }
    });

    // Today's classes
    const today = new Date();
    const dayOfWeek = today.getDay() || 7;
    const todayClasses = await ClassModel.find({
      teacherId,
      dayOfWeek: dayOfWeek,
      isActive: true
    })
    .populate('studentId', 'name')
    .sort({ startTime: 1 })
    .lean();

    res.json({
      success: true,
      dashboard: {
        counts: {
          students: studentCount,
          classes: classCount,
          assignments: assignmentCount,
          exams: examCount,
          pendingSubmissions: pendingSubmissions
        },
        todayClasses: todayClasses.map(cls => ({
          id: cls._id.toString(),
          subject: cls.subject,
          title: cls.title,
          startTime: cls.startTime,
          endTime: cls.endTime,
          studentName: cls.scope === 'INDIVIDUAL' ? cls.studentId?.name : 'All Students',
          location: cls.location
        }))
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch teacher dashboard' });
  }
});

// ========= CLASS MANAGEMENT =========

// POST /api/teacher/classes - Updated with scoping
app.post('/api/teacher/classes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { subject, title, dayOfWeek, startTime, endTime, colorHex, notes, location, scope, studentId } = req.body;

    if (!subject || !title || !dayOfWeek || !startTime) {
      return res.status(400).json({ error: 'Required fields: subject, title, dayOfWeek, startTime' });
    }

    if (scope === 'INDIVIDUAL' && studentId) {
      const isLinked = await ensureTeacherOwnsStudent(req.userId, studentId);
      if (!isLinked) {
        return res.status(403).json({ error: 'Not authorized to create class for this student' });
      }
    }

    const classData = {
      teacherId: req.userId,
      subject,
      title,
      dayOfWeek,
      startTime,
      endTime: endTime || startTime,
      colorHex: colorHex || '#3B82F6',
      notes: notes || '',
      location: location || '',
      scope: scope || 'ALL',
      studentId: scope === 'INDIVIDUAL' ? studentId : null,
      isActive: true
    };

    const newClass = await ClassModel.create(classData);

    // Send notification to linked students
    if (scope === 'ALL') {
      // Notify all linked students
      const links = await TeacherStudentLink.find({ 
        teacherId: req.userId, 
        isActive: true 
      });
      
      for (const link of links) {
        await createNotification(
          link.studentId,
          'CLASS',
          'New Class Added',
          `Your teacher added a new class: ${subject}`,
          { classId: newClass._id }
        );
      }
    } else if (scope === 'INDIVIDUAL' && studentId) {
      // Notify specific student
      await createNotification(
        studentId,
        'CLASS',
        'New Class Added',
        `Your teacher added a new class: ${subject}`,
        { classId: newClass._id }
      );
    }

    res.status(201).json({ success: true, classId: newClass._id });
  } catch (error) {
    console.error('Create class error:', error);
    res.status(500).json({ error: 'Failed to create class' });
  }
});

// PUT /api/teacher/classes/:id - Update class
app.put('/api/teacher/classes/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const classId = req.params.id;
    const { subject, title, dayOfWeek, startTime, endTime, colorHex, notes, location, scope, studentId } = req.body;

    const existingClass = await ClassModel.findOne({ _id: classId, teacherId: req.userId });
    if (!existingClass) {
      return res.status(404).json({ error: 'Class not found' });
    }

    const updateData = {
      subject: subject || existingClass.subject,
      title: title || existingClass.title,
      dayOfWeek: dayOfWeek || existingClass.dayOfWeek,
      startTime: startTime || existingClass.startTime,
      endTime: endTime || existingClass.endTime,
      colorHex: colorHex || existingClass.colorHex,
      notes: notes !== undefined ? notes : existingClass.notes,
      location: location !== undefined ? location : existingClass.location,
      scope: scope || existingClass.scope,
      studentId: scope === 'INDIVIDUAL' ? studentId : null
    };

    await ClassModel.findByIdAndUpdate(classId, updateData);
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to update class' });
  }
});

// DELETE /api/teacher/classes/:id - Delete class
app.delete('/api/teacher/classes/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const classId = req.params.id;

    const classItem = await ClassModel.findOneAndUpdate(
      { _id: classId, teacherId: req.userId },
      { isActive: false },
      { new: true }
    );

    if (!classItem) {
      return res.status(404).json({ error: 'Class not found' });
    }

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete class' });
  }
});

app.get('/api/teacher/classes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const classes = await ClassModel.find({ 
      teacherId: req.userId,
      isActive: true  // ✅ Only get active classes!
    })
    .populate('studentId', 'name')
    .sort({ dayOfWeek: 1, startTime: 1 })
    .lean();

    const formattedClasses = classes.map(cls => ({
      id: cls._id.toString(),
      subject: cls.subject,
      title: cls.title,
      dayOfWeek: cls.dayOfWeek,
      startTime: cls.startTime,
      endTime: cls.endTime,
      colorHex: cls.colorHex,
      notes: cls.notes,
      location: cls.location,
      scope: cls.scope,
      studentName: cls.studentId?.name,
      isActive: cls.isActive,
      createdAt: cls.createdAt
    }));

    res.json({ success: true, classes: formattedClasses });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch classes' });
  }
});

// ========= ASSIGNMENT MANAGEMENT =========

// GET /api/teacher/assignments - List Teacher Assignments
app.get('/api/teacher/assignments', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const assignments = await Assignment.find({ teacherId: req.userId })
      .sort({ dueAt: 1 })
      .lean();

    const formattedAssignments = assignments.map(assignment => ({
      id: assignment._id.toString(),
      title: assignment.title,
      dueAt: assignment.dueAt ? assignment.dueAt.toISOString() : null,
      description: assignment.description,  // ← Add this
      notes: assignment.notes,              // ← Add this
      priority: assignment.priority         // ← Add this
    }));

    res.json({ success: true, assignments: formattedAssignments });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch assignments' });
  }
});

// PUT /api/teacher/assignments/:id - Update Assignment
app.put('/api/teacher/assignments/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const assignmentId = req.params.id;
    const { title, description, dueAt, classId, notes, priority, scope, studentId, maxMarks } = req.body;

    const assignment = await Assignment.findOne({ _id: assignmentId, teacherId: req.userId });
    if (!assignment) {
      return res.status(404).json({ error: 'Assignment not found' });
    }

    const updateData = {
      title: title || assignment.title,
      description: description !== undefined ? description : assignment.description,
      dueAt: dueAt ? new Date(dueAt) : assignment.dueAt,
      classId: classId !== undefined ? classId : assignment.classId,
      notes: notes !== undefined ? notes : assignment.notes,
      priority: priority || assignment.priority,
      scope: scope || assignment.scope,
      studentId: scope === 'INDIVIDUAL' ? studentId : null,
      maxMarks: maxMarks !== undefined ? maxMarks : assignment.maxMarks,
      updatedAt: new Date()
    };

    await Assignment.findByIdAndUpdate(assignmentId, updateData);
    
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to update assignment' });
  }
});

// DELETE /api/teacher/assignments/:id - Delete Assignment
app.delete('/api/teacher/assignments/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const assignmentId = req.params.id;

    const assignment = await Assignment.findOneAndDelete({ 
      _id: assignmentId, 
      teacherId: req.userId 
    });

    if (!assignment) {
      return res.status(404).json({ error: 'Assignment not found' });
    }

    // Delete associated submissions
    await AssignmentSubmission.deleteMany({ assignmentId });
    
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete assignment' });
  }
});

// POST /api/teacher/assignments - Updated with scoping
app.post('/api/teacher/assignments', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { title, description, dueAt, classId, notes, priority, scope, studentId, maxMarks, attachments } = req.body;

    if (!title || !dueAt) {
      return res.status(400).json({ error: 'Title and due date are required' });
    }

    if (scope === 'INDIVIDUAL' && studentId) {
      const isLinked = await ensureTeacherOwnsStudent(req.userId, studentId);
      if (!isLinked) {
        return res.status(403).json({ error: 'Not authorized to create assignment for this student' });
      }
    }

    const assignment = await Assignment.create({
      teacherId: req.userId,
      title,
      description: description || '',
      dueAt: new Date(dueAt),
      classId: classId || null,
      notes: notes || '',
      priority: priority || 1,
      scope: scope || 'ALL',
      studentId: scope === 'INDIVIDUAL' ? studentId : null,
      maxMarks: maxMarks || null,
      attachments: attachments || []
    });

    // Notify students based on scope
    if (scope === 'ALL') {
      const links = await TeacherStudentLink.find({ teacherId: req.userId, isActive: true });
      for (const link of links) {
        await createNotification(
          link.studentId,
          'ASSIGNMENT',
          'New Assignment',
          `New assignment: ${title}`,
          { assignmentId: assignment._id }
        );
      }
    } else if (scope === 'INDIVIDUAL' && studentId) {
      await createNotification(
        studentId,
        'ASSIGNMENT',
        'New Individual Assignment',
        `New individual assignment: ${title}`,
        { assignmentId: assignment._id }
      );
    }

    res.status(201).json({ success: true, assignmentId: assignment._id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create assignment' });
  }
});

app.get('/api/teacher/assignments/:id/submissions', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const assignmentId = req.params.id;

    // Verify assignment belongs to teacher
    const assignment = await Assignment.findOne({ _id: assignmentId, teacherId: req.userId });
    if (!assignment) {
      return res.status(404).json({ error: 'Assignment not found' });
    }

    const submissions = await AssignmentSubmission.find({ assignmentId })
      .populate('studentId', 'name email studentCode avatar')
      .sort({ submittedAt: -1 })
      .lean();

    const formattedSubmissions = submissions.map(sub => ({
      id: sub._id.toString(),
      student: {
        id: sub.studentId._id.toString(),
        name: sub.studentId.name,
        email: sub.studentId.email,
        studentCode: sub.studentId.studentCode,
        avatar: sub.studentId.avatar
      },
      submittedAt: sub.submittedAt,
      notes: sub.notes,
      attachments: sub.attachments,
      marks: sub.marks,
      feedback: sub.feedback,
      status: sub.status,
      gradedAt: sub.gradedAt
    }));

    res.json({ success: true, submissions: formattedSubmissions });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch submissions' });
  }
});

// ========= GRADE SUBMISSION =========
app.put('/api/teacher/submissions/:id/grade', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const submissionId = req.params.id;
    const { marks, feedback } = req.body;

    const submission = await AssignmentSubmission.findById(submissionId).populate('assignmentId');
    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

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
      { assignmentId: submission.assignmentId._id, submissionId: submission._id }
    );

    return res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to grade submission' });
  }
});

// ========= NOTE MANAGEMENT =========

// GET /api/teacher/notes - List notes
app.get('/api/teacher/notes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const notes = await Note.find({ teacherId: req.userId })
      .sort({ createdAt: -1 })
      .lean();

    const formattedNotes = notes.map(note => ({
      id: note._id.toString(),
      title: note.title,
      content: note.content,  // ← Add this
      subject: note.subject   // ← Add this
    }));

    res.json({ success: true, notes: formattedNotes });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch notes' });
  }
});

// PUT /api/teacher/notes/:id - Update note
app.put('/api/teacher/notes/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const noteId = req.params.id;
    const { title, content, subject, scope, studentId } = req.body;

    const note = await Note.findOne({ _id: noteId, teacherId: req.userId });
    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }

    const updateData = {
      title: title || note.title,
      content: content !== undefined ? content : note.content,
      subject: subject !== undefined ? subject : note.subject,
      scope: scope || note.scope,
      studentId: scope === 'INDIVIDUAL' ? studentId : null,
      updatedAt: new Date()
    };

    await Note.findByIdAndUpdate(noteId, updateData);
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to update note' });
  }
});

// DELETE /api/teacher/notes/:id - Delete note
app.delete('/api/teacher/notes/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const noteId = req.params.id;

    const note = await Note.findOneAndDelete({ _id: noteId, teacherId: req.userId });
    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete note' });
  }
});

// POST /api/teacher/notes - Updated with scoping
app.post('/api/teacher/notes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { title, content, subject, scope, studentId, attachments } = req.body;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    if (scope === 'INDIVIDUAL' && studentId) {
      const isLinked = await ensureTeacherOwnsStudent(req.userId, studentId);
      if (!isLinked) {
        return res.status(403).json({ error: 'Not authorized to create note for this student' });
      }
    }

    const note = await Note.create({
      teacherId: req.userId,
      title,
      content: content || '',
      subject: subject || '',
      scope: scope || 'ALL',
      studentId: scope === 'INDIVIDUAL' ? studentId : null,
      attachments: attachments || []
    });

    // Notify students based on scope
    if (scope === 'ALL') {
      const links = await TeacherStudentLink.find({ teacherId: req.userId, isActive: true });
      for (const link of links) {
        await createNotification(
          link.studentId,
          'CLASS',
          'New Note Added',
          `New note: ${title}`,
          { noteId: note._id }
        );
      }
    } else if (scope === 'INDIVIDUAL' && studentId) {
      await createNotification(
        studentId,
        'CLASS',
        'New Note Added',
        `New note: ${title}`,
        { noteId: note._id }
      );
    }

    res.status(201).json({ success: true, noteId: note._id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create note' });
  }
});

// ========= EXAM MANAGEMENT =========

// GET /api/teacher/exams - List exams
app.get('/api/teacher/exams', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const exams = await Exam.find({ 
      teacherId: req.userId,
      isActive: true  // ← Filter out deleted exams
    })
    .sort({ whenAt: 1 })
    .lean();

    const formattedExams = exams.map(exam => ({
      id: exam._id.toString(),
      title: exam.title,
      whenAt: exam.whenAt.toISOString(),
      description: exam.description,  // ← Add this
      location: exam.location,        // ← Add this
      maxMarks: exam.maxMarks,        // ← Add this
      duration: exam.duration         // ← Add this
    }));

    res.json({ success: true, exams: formattedExams });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch exams' });
  }
});

// PUT /api/teacher/exams/:id - Update exam
app.put('/api/teacher/exams/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const examId = req.params.id;
    const { title, description, whenAt, classId, location, notes, maxMarks, duration, scope, studentId } = req.body;

    const exam = await Exam.findOne({ _id: examId, teacherId: req.userId });
    if (!exam) {
      return res.status(404).json({ error: 'Exam not found' });
    }

    const updateData = {
      title: title || exam.title,
      description: description !== undefined ? description : exam.description,
      whenAt: whenAt ? new Date(whenAt) : exam.whenAt,
      classId: classId !== undefined ? classId : exam.classId,
      location: location !== undefined ? location : exam.location,
      notes: notes !== undefined ? notes : exam.notes,
      maxMarks: maxMarks || exam.maxMarks,
      duration: duration || exam.duration,
      scope: scope || exam.scope,
      studentId: scope === 'INDIVIDUAL' ? studentId : null
    };

    await Exam.findByIdAndUpdate(examId, updateData);
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to update exam' });
  }
});

// DELETE /api/teacher/exams/:id - Delete exam
app.delete('/api/teacher/exams/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const examId = req.params.id;

    const exam = await Exam.findOneAndUpdate(
      { _id: examId, teacherId: req.userId },
      { isActive: false },
      { new: true }
    );

    if (!exam) {
      return res.status(404).json({ error: 'Exam not found' });
    }

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete exam' });
  }
});

// POST /api/teacher/exams - Updated with scoping
app.post('/api/teacher/exams', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { title, description, whenAt, classId, location, notes, maxMarks, duration, scope, studentId } = req.body;

    if (!title || !whenAt || !maxMarks) {
      return res.status(400).json({ error: 'Title, date, and max marks are required' });
    }

    if (scope === 'INDIVIDUAL' && studentId) {
      const isLinked = await ensureTeacherOwnsStudent(req.userId, studentId);
      if (!isLinked) {
        return res.status(403).json({ error: 'Not authorized to create exam for this student' });
      }
    }

    const exam = await Exam.create({
      teacherId: req.userId,
      title,
      description: description || '',
      whenAt: new Date(whenAt),
      classId: classId || null,
      location: location || '',
      notes: notes || '',
      maxMarks,
      duration: duration || 60,
      scope: scope || 'ALL',
      studentId: scope === 'INDIVIDUAL' ? studentId : null
    });

    // Notify students based on scope
    if (scope === 'ALL') {
      const links = await TeacherStudentLink.find({ teacherId: req.userId, isActive: true });
      for (const link of links) {
        await createNotification(
          link.studentId,
          'EXAM',
          'New Exam Scheduled',
          `New exam: ${title}`,
          { examId: exam._id }
        );
      }
    } else if (scope === 'INDIVIDUAL' && studentId) {
      await createNotification(
        studentId,
        'EXAM',
        'New Individual Exam',
        `New individual exam: ${title}`,
        { examId: exam._id }
      );
    }

    res.status(201).json({ success: true, examId: exam._id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create exam' });
  }
});

// ========= RESULT MANAGEMENT =========

// GET /api/teacher/results - List results
app.get('/api/teacher/results', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const results = await Result.find({ teacherId: req.userId })
      .populate('studentId', 'name studentCode')
      .sort({ createdAt: -1 })
      .lean();

    const formattedResults = results.map(result => ({
      id: result._id.toString(),
      studentName: result.studentId?.name,
      studentCode: result.studentId?.studentCode,
      examTitle: result.examTitle,
      subject: result.subject,
      totalMarks: result.totalMarks,
      obtainedMarks: result.obtainedMarks,
      remarks: result.remarks,
      createdAt: result.createdAt.toISOString()
    }));

    res.json({ success: true, results: formattedResults });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch results' });
  }
});

// PUT /api/teacher/results/:id - Update result
app.put('/api/teacher/results/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const resultId = req.params.id;
    const { examTitle, subject, totalMarks, obtainedMarks, remarks } = req.body;

    const result = await Result.findOne({ _id: resultId, teacherId: req.userId });
    if (!result) {
      return res.status(404).json({ error: 'Result not found' });
    }

    const updateData = {
      examTitle: examTitle || result.examTitle,
      subject: subject || result.subject,
      totalMarks: totalMarks !== undefined ? totalMarks : result.totalMarks,
      obtainedMarks: obtainedMarks !== undefined ? obtainedMarks : result.obtainedMarks,
      remarks: remarks !== undefined ? remarks : result.remarks
    };

    if (updateData.totalMarks && updateData.obtainedMarks) {
      const percentage = (updateData.obtainedMarks / updateData.totalMarks) * 100;
      updateData.percentage = Math.round(percentage * 100) / 100;
      updateData.grade = calculateGrade(percentage);
    }

    await Result.findByIdAndUpdate(resultId, updateData);
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to update result' });
  }
});

// DELETE /api/teacher/results/:id - Delete result
app.delete('/api/teacher/results/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const resultId = req.params.id;

    const result = await Result.findOneAndDelete({ _id: resultId, teacherId: req.userId });
    if (!result) {
      return res.status(404).json({ error: 'Result not found' });
    }

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete result' });
  }
});

// POST /api/teacher/results - Updated with scoping
app.post('/api/teacher/results', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { studentId, examTitle, examId, subject, totalMarks, obtainedMarks, remarks } = req.body;

    if (!studentId || !examTitle || totalMarks == null || obtainedMarks == null) {
      return res.status(400).json({ error: 'Student, exam title, and marks are required' });
    }

    const isLinked = await ensureTeacherOwnsStudent(req.userId, studentId);
    if (!isLinked) {
      return res.status(403).json({ error: 'Not authorized to add result for this student' });
    }

    const percentage = (obtainedMarks / totalMarks) * 100;
    const grade = calculateGrade(percentage);

    const result = await Result.create({
      teacherId: req.userId,
      studentId,
      examId: examId || null,
      examTitle,
      subject: subject || 'General',
      totalMarks,
      obtainedMarks,
      percentage: Math.round(percentage * 100) / 100,
      grade,
      remarks: remarks || '',
      published: true,
      publishedAt: new Date()
    });

    // Notify student
    await createNotification(
      studentId,
      'RESULT',
      'New Result Published',
      `Result published for: ${examTitle}`,
      { resultId: result._id, examTitle }
    );

    res.status(201).json({ success: true, resultId: result._id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create result' });
  }
});

// ========= ATTENDANCE MANAGEMENT =========
app.post('/api/teacher/attendance', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { classId, date, marks } = req.body;

    if (!classId || !date || !Array.isArray(marks)) {
      return res.status(400).json({ error: 'Class ID, date, and marks array are required' });
    }

    // Validate class belongs to teacher
    const classExists = await ClassModel.findOne({ _id: classId, teacherId: req.userId });
    if (!classExists) {
      return res.status(404).json({ error: 'Class not found' });
    }

    // Validate each student link
    for (const mark of marks) {
      if (!mark || !mark.studentId) continue;
      const isLinked = await ensureTeacherOwnsStudent(req.userId, mark.studentId);
      if (!isLinked) {
        return res.status(403).json({ error: `Not linked to student ${mark.studentId}` });
      }
    }

    // Upsert attendance
    await Attendance.updateOne(
      { teacherId: req.userId, classId, date },
      { $set: { marks, createdAt: new Date() } },
      { upsert: true }
    );

    res.json({ success: true, message: 'Attendance recorded successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record attendance' });
  }
});

// ========= ANALYTICS ENDPOINTS =========

// GET /api/teacher/analytics/overview - Teacher dashboard overview
app.get('/api/teacher/analytics/overview', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;

    const studentCount = await TeacherStudentLink.countDocuments({ teacherId, isActive: true });
    const classCount = await ClassModel.countDocuments({ teacherId, isActive: true });
    
    // Pending assignments (not yet graded submissions)
    const assignments = await Assignment.find({ teacherId }).select('_id');
    const assignmentIds = assignments.map(a => a._id);
    const pendingAssignments = await AssignmentSubmission.countDocuments({
      assignmentId: { $in: assignmentIds },
      status: { $in: ['SUBMITTED', 'LATE'] }
    });

    // Upcoming exams (next 30 days)
    const now = new Date();
    const next30Days = new Date();
    next30Days.setDate(next30Days.getDate() + 30);
    const upcomingExams = await Exam.countDocuments({
      teacherId,
      whenAt: { $gte: now, $lte: next30Days },
      isActive: true
    });

    res.json({
      success: true,
      studentCount,
      classCount,
      pendingAssignments,
      upcomingExams
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch analytics overview' });
  }
});

// GET /api/teacher/analytics/:studentId - Per-student analytics
app.get('/api/teacher/analytics/:studentId', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const studentId = req.params.studentId;
    const teacherId = req.userId;

    // Verify student is linked
    const isLinked = await ensureTeacherOwnsStudent(teacherId, studentId);
    if (!isLinked) {
      return res.status(403).json({ error: 'Not authorized to view this student analytics' });
    }

    // Get attendance records for this student
    const attendanceRecords = await Attendance.find({ teacherId }).lean();
    
    let attended = 0;
    let missed = 0;
    let cancelled = 0;

    attendanceRecords.forEach(record => {
      const studentMark = record.marks.find(m => m.studentId.toString() === studentId);
      if (studentMark) {
        if (studentMark.present) {
          attended++;
        } else {
          missed++;
        }
      }
    });

    const total = attended + missed;
    const attendanceRate = total > 0 ? (attended / total) * 100 : null;

    res.json({
      success: true,
      attended,
      missed,
      cancelled,
      attendanceRate: attendanceRate ? Math.round(attendanceRate * 100) / 100 : null
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch student analytics' });
  }
});

// ========= NOTIFICATION ROUTES =========
app.get('/api/notifications', authRequired, async (req, res) => {
  try {
    const { page = 1, limit = 20, unread } = req.query;
    const skip = (page - 1) * limit;

    let query = { userId: req.userId };
    if (unread === 'true') {
      query.read = false;
    }

    const notifications = await Notification.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const unreadCount = await Notification.countDocuments({ userId: req.userId, read: false });

    res.json({
      success: true,
      notifications: notifications.map(notif => ({
        id: notif._id.toString(),
        type: notif.type,
        title: notif.title,
        message: notif.message,
        data: notif.data,
        read: notif.read,
        priority: notif.priority,
        createdAt: notif.createdAt
      })),
      unreadCount,
      pagination: { page: parseInt(page), limit: parseInt(limit) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.patch('/api/notifications/:id/read', authRequired, async (req, res) => {
  try {
    await Notification.findByIdAndUpdate(req.params.id, { 
      read: true, 
      readAt: new Date() 
    });
    res.json({ success: true, message: 'Notification marked as read' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update notification' });
  }
});

app.patch('/api/notifications/read-all', authRequired, async (req, res) => {
  try {
    await Notification.updateMany(
      { userId: req.userId, read: false },
      { read: true, readAt: new Date() }
    );
    res.json({ success: true, message: 'All notifications marked as read' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update notifications' });
  }
});

// ========= PLANNER/TASK MANAGEMENT =========

// GET /api/planner/tasks - Get all tasks for current user
app.get('/api/planner/tasks', authRequired, async (req, res) => {
  try {
    const { startDate, endDate, type, completed } = req.query;
    
    let query = { userId: req.userId };
    
    // Filter by date range
    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }
    
    // Filter by type
    if (type && type !== 'ALL') {
      query.type = type;
    }
    
    // Filter by completion status
    if (completed !== undefined) {
      query.completed = completed === 'true';
    }
    
    const tasks = await PlannerTask.find(query)
      .sort({ date: 1, startTime: 1 })
      .lean();
    
    const formatted = tasks.map(task => ({
      id: task._id.toString(),
      title: task.title,
      description: task.description,
      date: task.date.toISOString(),
      startTime: task.startTime,
      endTime: task.endTime,
      type: task.type,
      location: task.location,
      priority: task.priority,
      completed: task.completed,
      completedAt: task.completedAt,
      notifyBefore: task.notifyBefore,
      repeatType: task.repeatType,
      repeatUntil: task.repeatUntil,
      colorHex: task.colorHex,
      notes: task.notes,
      createdAt: task.createdAt.toISOString(),
      updatedAt: task.updatedAt.toISOString()
    }));
    
    res.json({ success: true, tasks: formatted });
  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// POST /api/planner/tasks - Create new task
app.post('/api/planner/tasks', authRequired, async (req, res) => {
  try {
    const {
      title, description, date, startTime, endTime, type, location,
      priority, notifyBefore, repeatType, repeatUntil, colorHex, notes
    } = req.body;
    
    if (!title || !date) {
      return res.status(400).json({ error: 'Title and date are required' });
    }
    
    const task = await PlannerTask.create({
      userId: req.userId,
      title,
      description: description || '',
      date: new Date(date),
      startTime: startTime || null,
      endTime: endTime || null,
      type: type || 'STUDY',
      location: location || '',
      priority: priority !== undefined ? priority : 1,
      notifyBefore: notifyBefore !== undefined ? notifyBefore : 30,
      repeatType: repeatType || 'NONE',
      repeatUntil: repeatUntil ? new Date(repeatUntil) : null,
      colorHex: colorHex || '#3B82F6',
      notes: notes || ''
    });
    
    res.status(201).json({ success: true, taskId: task._id.toString() });
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// PUT /api/planner/tasks/:id - Update task
app.put('/api/planner/tasks/:id', authRequired, async (req, res) => {
  try {
    const taskId = req.params.id;
    const updates = req.body;
    
    const task = await PlannerTask.findOne({ _id: taskId, userId: req.userId });
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    // Update allowed fields
    const allowedUpdates = [
      'title', 'description', 'date', 'startTime', 'endTime', 'type',
      'location', 'priority', 'notifyBefore', 'repeatType', 'repeatUntil',
      'colorHex', 'notes'
    ];
    
    allowedUpdates.forEach(field => {
      if (updates[field] !== undefined) {
        task[field] = updates[field];
      }
    });
    
    task.updatedAt = new Date();
    await task.save();
    
    res.status(204).send();
  } catch (error) {
    console.error('Update task error:', error);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

// PATCH /api/planner/tasks/:id/complete - Toggle completion
app.patch('/api/planner/tasks/:id/complete', authRequired, async (req, res) => {
  try {
    const taskId = req.params.id;
    const { completed } = req.body;
    
    const task = await PlannerTask.findOne({ _id: taskId, userId: req.userId });
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    task.completed = completed !== undefined ? completed : !task.completed;
    task.completedAt = task.completed ? new Date() : null;
    task.updatedAt = new Date();
    await task.save();
    
    res.json({ success: true, completed: task.completed });
  } catch (error) {
    console.error('Toggle completion error:', error);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

// DELETE /api/planner/tasks/:id - Delete task
app.delete('/api/planner/tasks/:id', authRequired, async (req, res) => {
  try {
    const taskId = req.params.id;
    
    const task = await PlannerTask.findOneAndDelete({ _id: taskId, userId: req.userId });
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    res.status(204).send();
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// GET /api/planner/stats - Get planner statistics
app.get('/api/planner/stats', authRequired, async (req, res) => {
  try {
    const userId = req.userId;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    // Today's tasks
    const todayTasks = await PlannerTask.countDocuments({
      userId,
      date: { $gte: today, $lt: tomorrow }
    });
    
    const todayCompleted = await PlannerTask.countDocuments({
      userId,
      date: { $gte: today, $lt: tomorrow },
      completed: true
    });
    
    // This week's tasks
    const weekStart = new Date(today);
    weekStart.setDate(today.getDate() - today.getDay());
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 7);
    
    const weekTasks = await PlannerTask.countDocuments({
      userId,
      date: { $gte: weekStart, $lt: weekEnd }
    });
    
    const weekCompleted = await PlannerTask.countDocuments({
      userId,
      date: { $gte: weekStart, $lt: weekEnd },
      completed: true
    });
    
    // Overdue tasks
    const overdue = await PlannerTask.countDocuments({
      userId,
      date: { $lt: today },
      completed: false
    });
    
    res.json({
      success: true,
      stats: {
        todayTotal: todayTasks,
        todayCompleted,
        weekTotal: weekTasks,
        weekCompleted,
        overdue,
        todayProgress: todayTasks > 0 ? Math.round((todayCompleted / todayTasks) * 100) : 0,
        weekProgress: weekTasks > 0 ? Math.round((weekCompleted / weekTasks) * 100) : 0
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// ========= RANKING ENDPOINTS =========

// GET /api/student/rankings - Get all rankings for linked teachers
app.get('/api/student/rankings', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, rankings: [] });
    }
    
    // Get all published results for this student's linked teachers
    const results = await Result.find({
      teacherId: { $in: linkedTeacherIds },
      published: true
    })
    .populate('teacherId', 'name')
    .populate('studentId', 'name')
    .lean();
    
    // Group results by teacher and exam
    const rankingsByTeacher = {};
    
    for (const teacherId of linkedTeacherIds) {
      const teacher = await User.findById(teacherId).select('name');
      const teacherResults = results.filter(r => r.teacherId._id.toString() === teacherId.toString());
      
      // Group by exam
      const examGroups = {};
      teacherResults.forEach(result => {
        const key = `${result.examTitle}_${result.subject}`;
        if (!examGroups[key]) {
          examGroups[key] = [];
        }
        examGroups[key].push(result);
      });
      
      // Calculate rankings for each exam
      const rankings = [];
      for (const [key, examResults] of Object.entries(examGroups)) {
        const sortedResults = examResults.sort((a, b) => {
          const percentageA = (a.obtainedMarks / a.totalMarks) * 100;
          const percentageB = (b.obtainedMarks / b.totalMarks) * 100;
          return percentageB - percentageA;
        });
        
        const rankedResults = sortedResults.map((result, index) => ({
          rank: index + 1,
          studentId: result.studentId._id.toString(),
          studentName: result.studentId.name,
          obtainedMarks: result.obtainedMarks,
          totalMarks: result.totalMarks,
          percentage: Math.round((result.obtainedMarks / result.totalMarks) * 100 * 100) / 100,
          grade: result.grade,
          isCurrentStudent: result.studentId._id.toString() === studentId.toString()
        }));
        
        rankings.push({
          examTitle: examResults[0].examTitle,
          subject: examResults[0].subject,
          date: examResults[0].createdAt,
          totalStudents: rankedResults.length,
          rankings: rankedResults
        });
      }
      
      if (rankings.length > 0) {
        rankingsByTeacher[teacherId.toString()] = {
          teacherId: teacherId.toString(),
          teacherName: teacher.name,
          exams: rankings
        };
      }
    }
    
    res.json({ 
      success: true, 
      rankings: Object.values(rankingsByTeacher)
    });
  } catch (error) {
    console.error('Get student rankings error:', error);
    res.status(500).json({ error: 'Failed to fetch rankings' });
  }
});

// GET /api/teacher/rankings - Teacher view of exam rankings
app.get('/api/teacher/rankings', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;
    
    // Get all results created by this teacher
    const results = await Result.find({
      teacherId,
      published: true
    })
    .populate('studentId', 'name studentCode')
    .lean();
    
    // Group by exam
    const examGroups = {};
    results.forEach(result => {
      const key = `${result.examTitle}_${result.subject}_${result.createdAt.toDateString()}`;
      if (!examGroups[key]) {
        examGroups[key] = {
          examTitle: result.examTitle,
          subject: result.subject,
          date: result.createdAt,
          results: []
        };
      }
      examGroups[key].results.push(result);
    });
    
    // Calculate rankings for each exam
    const rankings = [];
    for (const [key, examData] of Object.entries(examGroups)) {
      const sortedResults = examData.results.sort((a, b) => {
        const percentageA = (a.obtainedMarks / a.totalMarks) * 100;
        const percentageB = (b.obtainedMarks / b.totalMarks) * 100;
        return percentageB - percentageA;
      });
      
      const rankedResults = sortedResults.map((result, index) => ({
        rank: index + 1,
        studentId: result.studentId._id.toString(),
        studentName: result.studentId.name,
        studentCode: result.studentId.studentCode,
        obtainedMarks: result.obtainedMarks,
        totalMarks: result.totalMarks,
        percentage: Math.round((result.obtainedMarks / result.totalMarks) * 100 * 100) / 100,
        grade: result.grade
      }));
      
      rankings.push({
        examTitle: examData.examTitle,
        subject: examData.subject,
        date: examData.date,
        totalStudents: rankedResults.length,
        topPerformer: rankedResults[0]?.studentName,
        averagePercentage: Math.round(
          rankedResults.reduce((sum, r) => sum + r.percentage, 0) / rankedResults.length * 100
        ) / 100,
        rankings: rankedResults
      });
    }
    
    rankings.sort((a, b) => new Date(b.date) - new Date(a.date));
    
    res.json({ 
      success: true, 
      rankings
    });
  } catch (error) {
    console.error('Get teacher rankings error:', error);
    res.status(500).json({ error: 'Failed to fetch rankings' });
  }
});

// ========= 404 HANDLER =========
app.use('*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// ========= ERROR HANDLER =========
app.use((error, req, res, next) => {
  console.error('Server error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// ========= START SERVER =========
server.listen(PORT, () => {
  console.log(`🚀 Tuition Manager Backend running on port ${PORT}`);
  console.log(`📱 Mobile-optimized API ready`);
  console.log(`🔗 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️  Database: ${MONGODB_URI}`);
});
