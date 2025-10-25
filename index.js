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

// ========= SECURITY & MIDDLEWARE =========
app.use(helmet());
app.use(mongoSanitize());
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:19006',
    'exp://192.168.*.*:19000',
    'capacitor://localhost',
    'ionic://localhost'
  ],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP' }
});
app.use('/api/', limiter);

// ========= CONFIG =========
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/tuitionmanager';
const JWT_SECRET = process.env.JWT_SECRET || 'mobile_app_secret_key_2024';
const PORT = process.env.PORT || 3001;

// ========= DATABASE CONNECTION =========
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
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
  fcmToken: { type: String }, // For push notifications
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

// Teacher-Student Link
const TeacherStudentLinkSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
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
  priority: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH'], default: 'MEDIUM' },
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

    const user = await User.findOne({ email: email.toLowerCase() });
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

// ========= STUDENT ROUTES =========
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

app.get('/api/student/classes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;

    const links = await TeacherStudentLink.find({ studentId: req.userId, isActive: true });
    const teacherIds = links.map(link => link.teacherId);

    const classes = await ClassModel.find({
      teacherId: { $in: teacherIds },
      isActive: true,
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: req.userId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ dayOfWeek: 1, startTime: 1 })
    .skip(skip)
    .limit(parseInt(limit))
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
      teacherName: cls.teacherId.name,
      scope: cls.scope
    }));

    res.json({ success: true, classes: formattedClasses });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch classes' });
  }
});

app.get('/api/student/assignments', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const skip = (page - 1) * limit;

    const links = await TeacherStudentLink.find({ studentId: req.userId, isActive: true });
    const teacherIds = links.map(link => link.teacherId);

    let query = {
      teacherId: { $in: teacherIds },
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: req.userId }
      ]
    };

    if (status && status !== 'ALL') {
      query.status = status;
    }

    const assignments = await Assignment.find(query)
      .populate('teacherId', 'name')
      .sort({ dueAt: 1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    // Check submission status for each assignment
    const assignmentsWithStatus = await Promise.all(
      assignments.map(async (assignment) => {
        const submission = await AssignmentSubmission.findOne({
          assignmentId: assignment._id,
          studentId: req.userId
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

    res.json({ 
      success: true, 
      assignments: assignmentsWithStatus,
      pagination: { page: parseInt(page), limit: parseInt(limit) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch assignments' });
  }
});

app.post('/api/student/assignments/:id/submit', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const assignmentId = req.params.id;
    const { notes, attachments } = req.body;

    const assignment = await Assignment.findById(assignmentId);
    if (!assignment) {
      return res.status(404).json({ error: 'Assignment not found' });
    }

    // Verify student is linked to teacher
    const isLinked = await ensureTeacherOwnsStudent(assignment.teacherId, req.userId);
    if (!isLinked) {
      return res.status(403).json({ error: 'Not authorized to submit this assignment' });
    }

    const submissionData = {
      notes: notes || '',
      attachments: attachments || [],
      submittedAt: new Date(),
      status: new Date() > new Date(assignment.dueAt) ? 'LATE' : 'SUBMITTED'
    };

    const submission = await AssignmentSubmission.findOneAndUpdate(
      { assignmentId, studentId: req.userId },
      submissionData,
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
      `${student.name} submitted: ${assignment.title}`,
      { assignmentId, studentId: req.userId, submissionId: submission._id }
    );

    res.json({ 
      success: true, 
      message: 'Assignment submitted successfully',
      submissionId: submission._id 
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to submit assignment' });
  }
});

app.get('/api/student/notes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const links = await TeacherStudentLink.find({ studentId: req.userId, isActive: true });
    const teacherIds = links.map(link => link.teacherId);

    const notes = await Note.find({
      teacherId: { $in: teacherIds },
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: req.userId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(parseInt(limit))
    .lean();

    const formattedNotes = notes.map(note => ({
      id: note._id.toString(),
      title: note.title,
      content: note.content,
      subject: note.subject,
      category: note.category,
      teacherName: note.teacherId.name,
      isPinned: note.isPinned,
      attachments: note.attachments || [],
      createdAt: note.createdAt
    }));

    res.json({ 
      success: true, 
      notes: formattedNotes,
      pagination: { page: parseInt(page), limit: parseInt(limit) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notes' });
  }
});

app.get('/api/student/exams', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const links = await TeacherStudentLink.find({ studentId: req.userId, isActive: true });
    const teacherIds = links.map(link => link.teacherId);

    const exams = await Exam.find({
      teacherId: { $in: teacherIds },
      isActive: true,
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: req.userId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ whenAt: 1 })
    .skip(skip)
    .limit(parseInt(limit))
    .lean();

    const formattedExams = exams.map(exam => ({
      id: exam._id.toString(),
      title: exam.title,
      description: exam.description,
      whenAt: exam.whenAt,
      location: exam.location,
      duration: exam.duration,
      maxMarks: exam.maxMarks,
      teacherName: exam.teacherId.name,
      notes: exam.notes
    }));

    res.json({ 
      success: true, 
      exams: formattedExams,
      pagination: { page: parseInt(page), limit: parseInt(limit) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch exams' });
  }
});

app.get('/api/student/results', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const results = await Result.find({ 
      studentId: req.userId,
      published: true 
    })
    .populate('teacherId', 'name')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(parseInt(limit))
    .lean();

    const formattedResults = results.map(result => {
      const percentage = (result.obtainedMarks / result.totalMarks) * 100;
      return {
        id: result._id.toString(),
        examTitle: result.examTitle,
        subject: result.subject,
        totalMarks: result.totalMarks,
        obtainedMarks: result.obtainedMarks,
        percentage: Math.round(percentage * 100) / 100,
        grade: result.grade || calculateGrade(percentage),
        remarks: result.remarks,
        teacherName: result.teacherId.name,
        publishedAt: result.publishedAt,
        createdAt: result.createdAt
      };
    });

    res.json({ 
      success: true, 
      results: formattedResults,
      pagination: { page: parseInt(page), limit: parseInt(limit) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch results' });
  }
});

app.get('/api/student/dashboard', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const links = await TeacherStudentLink.find({ studentId: req.userId, isActive: true });
    const teacherIds = links.map(link => link.teacherId);

    // Today's classes
    const today = new Date();
    const dayOfWeek = today.getDay() || 7; // Convert Sunday (0) to 7
    const todayClasses = await ClassModel.find({
      teacherId: { $in: teacherIds },
      dayOfWeek: dayOfWeek,
      isActive: true,
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: req.userId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ startTime: 1 })
    .lean();

    // Upcoming assignments (next 7 days)
    const nextWeek = new Date();
    nextWeek.setDate(nextWeek.getDate() + 7);
    
    const upcomingAssignments = await Assignment.find({
      teacherId: { $in: teacherIds },
      dueAt: { $gte: today, $lte: nextWeek },
      $or: [
        { scope: 'ALL' },
        { scope: 'INDIVIDUAL', studentId: req.userId }
      ]
    })
    .populate('teacherId', 'name')
    .sort({ dueAt: 1 })
    .limit(5)
    .lean();

    // Recent notifications
    const recentNotifications = await Notification.find({ userId: req.userId })
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

app.post('/api/teacher/students/link', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { studentCode } = req.body;

    if (!studentCode) {
      return res.status(400).json({ error: 'Student code is required' });
    }

    const student = await User.findOne({ studentCode, role: 'STUDENT', isActive: true });
    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }

    // Check if already linked
    const existingLink = await TeacherStudentLink.findOne({ teacherId: req.userId, studentId: student._id });
    if (existingLink) {
      return res.status(409).json({ error: 'Student is already linked' });
    }

    await TeacherStudentLink.create({
      teacherId: req.userId,
      studentId: student._id
    });

    // Notify student
    const teacher = await User.findById(req.userId);
    await createNotification(
      student._id,
      'SYSTEM',
      'New Teacher Connection',
      `You have been linked to ${teacher.name}`,
      { teacherId: req.userId }
    );

    res.json({ success: true, message: 'Student linked successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to link student' });
  }
});

app.get('/api/teacher/students', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const links = await TeacherStudentLink.find({ teacherId: req.userId, isActive: true })
      .populate('studentId', 'name email mobile studentCode avatar lastLogin')
      .sort({ createdAt: -1 })
      .lean();

    const students = links.map(link => ({
      id: link.studentId._id.toString(),
      name: link.studentId.name,
      email: link.studentId.email,
      mobile: link.studentId.mobile,
      studentCode: link.studentId.studentCode,
      avatar: link.studentId.avatar,
      lastLogin: link.studentId.lastLogin,
      linkedAt: link.createdAt
    }));

    res.json({ success: true, students });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

// ========= CLASS MANAGEMENT =========
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
      endTime: endTime || startTime, // Default to startTime if not provided
      colorHex: colorHex || '#3B82F6',
      notes: notes || '',
      location: location || '',
      scope: scope || 'ALL',
      studentId: scope === 'INDIVIDUAL' ? studentId : null
    };

    const newClass = await ClassModel.create(classData);

    // Notify students
    if (scope === 'ALL') {
      const students = await TeacherStudentLink.find({ teacherId: req.userId }).populate('studentId');
      for (const link of students) {
        await createNotification(
          link.studentId._id,
          'CLASS',
          'New Class Scheduled',
          `New class: ${title} (${subject})`,
          { classId: newClass._id }
        );
      }
    } else if (studentId) {
      await createNotification(
        studentId,
        'CLASS',
        'New Individual Class',
        `New individual class: ${title} (${subject})`,
        { classId: newClass._id }
      );
    }

    res.status(201).json({ success: true, classId: newClass._id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create class' });
  }
});

app.get('/api/teacher/classes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const classes = await ClassModel.find({ teacherId: req.userId })
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
      priority: priority || 'MEDIUM',
      scope: scope || 'ALL',
      studentId: scope === 'INDIVIDUAL' ? studentId : null,
      maxMarks: maxMarks || null,
      attachments: attachments || []
    });

    // Notify students
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

// ========= HEALTH CHECK =========
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Tuition Manager API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
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
