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
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  },
  pingTimeout: 60000,        // Wait 60s for pong before disconnect
  pingInterval: 25000,       // Send ping every 25s
  upgradeTimeout: 30000,     // Connection upgrade timeout
  transports: ['websocket', 'polling']
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

// ========= CHAT & FILE UPLOAD SETUP =========
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    // Added audio extensions for voice messages: m4a|mp3|mp4|aac|wav|ogg|3gpp
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|xls|xlsx|txt|zip|m4a|mp3|mp4|aac|wav|ogg|3gpp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype) || file.mimetype.startsWith('audio/');
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Invalid file type'));
  }
});

app.use('/uploads', express.static(uploadDir));

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
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }, // ← ADD COMMA HERE
  subscriptionStatus: { 
    type: String, 
    enum: ['free', 'trial', 'active', 'expired'], 
    default: 'free' 
  },
  subscriptionExpiry: { type: Date },
  totalGameXP: { type: Number, default: 0 },
  gamesPlayed: { type: Number, default: 0 }
});

// Teacher-Student Link
const TeacherStudentLinkSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true },
  isActive: { type: Boolean, default: true },
  linkedAt: { type: Date, default: Date.now },
  unlinkedAt: { type: Date },
  // ✅ NEW: Blocking fields
  isBlocked: { type: Boolean, default: false },
  blockedAt: { type: Date },
  blockedBy: { type: String, enum: ['student', 'teacher'] }
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
  priority: { type: Number, enum: [0, 1, 2], default: 1 },
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
  type: { type: String, enum: ['ASSIGNMENT', 'EXAM', 'ATTENDANCE', 'RESULT', 'CLASS', 'SYSTEM', 'CHAT'], required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  data: { type: Schema.Types.Mixed },
  read: { type: Boolean, default: false },
  readAt: { type: Date },
  priority: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH'], default: 'MEDIUM' },
  createdAt: { type: Date, default: Date.now }
});

// Planner/Task Schema
const PlannerTaskSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String },
  date: { type: Date, required: true },
  startTime: { type: String },
  endTime: { type: String },
  type: { type: String, enum: ['STUDY', 'CLASS', 'EXERCISE', 'WORK', 'PERSONAL', 'OTHER'], default: 'STUDY' },
  location: { type: String },
  priority: { type: Number, enum: [0, 1, 2], default: 1 },
  completed: { type: Boolean, default: false },
  completedAt: { type: Date },
  notifyBefore: { type: Number, default: 30 },
  repeatType: { type: String, enum: ['NONE', 'DAILY', 'WEEKLY', 'MONTHLY'], default: 'NONE' },
  repeatUntil: { type: Date },
  colorHex: { type: String, default: '#3B82F6' },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Conversation Schema
const ConversationSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true },
  studentId: { type: Types.ObjectId, ref: 'User', required: true },
  lastMessage: { type: String },
  lastMessageAt: { type: Date, default: Date.now },
  lastMessageSenderId: { type: Types.ObjectId, ref: 'User' },
  unreadCountTeacher: { type: Number, default: 0 },
  unreadCountStudent: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
ConversationSchema.index({ teacherId: 1, studentId: 1 }, { unique: true });

// Message Schema
const MessageSchema = new Schema({
  conversationId: { type: Types.ObjectId, ref: 'Conversation', required: true },
  senderId: { type: Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: Types.ObjectId, ref: 'User', required: true },
  content: { type: String },
  type: { type: String, enum: ['TEXT', 'IMAGE', 'FILE', 'PDF', 'VOICE'], default: 'TEXT' },  // ← ADD 'VOICE' here
  fileUrl: { type: String },
  fileName: { type: String },
  fileSize: { type: Number },
  mimeType: { type: String },
  duration: { type: Number },  // ← ADD THIS LINE (voice duration in seconds)
  iv: { type: String },
  delivered: { type: Boolean, default: false },
  deliveredAt: { type: Date },
  read: { type: Boolean, default: false },
  readAt: { type: Date },
  deleted: { type: Boolean, default: false },
  deletedAt: { type: Date },
  deletedBy: { type: Types.ObjectId, ref: 'User' },
  deletedForUsers: [{ type: Types.ObjectId, ref: 'User' }],
  replyTo: {
    messageId: { type: String },
    content: { type: String },
    senderId: { type: Types.ObjectId, ref: 'User' },
    senderName: { type: String },
    type: { type: String, enum: ['TEXT', 'IMAGE', 'FILE', 'PDF', 'VOICE'], default: 'TEXT' }  // ← ADD 'VOICE' here too
  },
  createdAt: { type: Date, default: Date.now }
});
MessageSchema.index({ conversationId: 1, createdAt: -1 });

// User Block Schema
const UserBlockSchema = new Schema({
  blockerId: { type: Types.ObjectId, ref: 'User', required: true },
  blockedId: { type: Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});
UserBlockSchema.index({ blockerId: 1, blockedId: 1 }, { unique: true });

// ========= SECTION & GROUP CLASS SCHEMAS =========

// Section Schema - for grouping students
const SectionSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  name: { type: String, required: true },
  description: { type: String },
  colorHex: { type: String, default: '#3B82F6' },
  studentIds: [{ type: Types.ObjectId, ref: 'User' }],
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
SectionSchema.index({ teacherId: 1, name: 1 });

// Group Class Schema
const GroupClassSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  subject: { type: String, required: true },
  description: { type: String },
  scheduledAt: { type: Date, required: true, index: true },
  duration: { type: Number, required: true, default: 60 },
  sectionId: { type: Types.ObjectId, ref: 'Section' },
  studentIds: [{ type: Types.ObjectId, ref: 'User' }],
  isForAllStudents: { type: Boolean, default: false },
  allowStudentVideo: { type: Boolean, default: true },
  allowStudentAudio: { type: Boolean, default: true },
  allowChat: { type: Boolean, default: true },
  allowScreenShare: { type: Boolean, default: false },
  allowWhiteboard: { type: Boolean, default: true },
  recordSession: { type: Boolean, default: false },
  status: { type: String, enum: ['SCHEDULED', 'LIVE', 'ENDED', 'CANCELLED'], default: 'SCHEDULED' },
  startedAt: { type: Date },
  endedAt: { type: Date },
  sessionId: { type: String, unique: true, sparse: true },
  recordingUrl: { type: String },
  colorHex: { type: String, default: '#10B981' },
  notes: { type: String },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
GroupClassSchema.index({ teacherId: 1, scheduledAt: 1 });

// Group Call Participant Schema
const GroupCallParticipantSchema = new Schema({
  sessionId: { type: String, required: true, index: true },
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  role: { type: String, enum: ['HOST', 'PARTICIPANT'], required: true },
  peerId: { type: String },
  socketId: { type: String },
  isVideoEnabled: { type: Boolean, default: false },
  isAudioEnabled: { type: Boolean, default: false },
  isScreenSharing: { type: Boolean, default: false },
  isHandRaised: { type: Boolean, default: false },
  isVideoMutedByHost: { type: Boolean, default: false },
  isAudioMutedByHost: { type: Boolean, default: false },
  connectionState: { type: String, enum: ['CONNECTING', 'CONNECTED', 'DISCONNECTED'], default: 'CONNECTING' },
  joinedAt: { type: Date, default: Date.now },
  leftAt: { type: Date }
});
GroupCallParticipantSchema.index({ sessionId: 1, userId: 1 }, { unique: true });

// Class Chat Message Schema
const ClassChatMessageSchema = new Schema({
  sessionId: { type: String, required: true, index: true },
  senderId: { type: Types.ObjectId, ref: 'User', required: true },
  senderName: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['TEXT', 'FILE', 'SYSTEM'], default: 'TEXT' },
  fileUrl: { type: String },
  isPrivate: { type: Boolean, default: false },
  recipientId: { type: Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});
ClassChatMessageSchema.index({ sessionId: 1, createdAt: 1 });

// Whiteboard Data Schema
const WhiteboardDataSchema = new Schema({
  sessionId: { type: String, required: true, unique: true },
  strokes: { type: Schema.Types.Mixed, default: [] },
  images: { type: Schema.Types.Mixed, default: [] },
  lastUpdatedBy: { type: Types.ObjectId, ref: 'User' },
  updatedAt: { type: Date, default: Date.now }
});

// ========= GAME SCHEMAS (ADD AFTER UserBlockSchema) =========

// User XP Tracking
const UserXPSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true, unique: true },
  totalXP: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  quizXP: { type: Number, default: 0 },
  mathXP: { type: Number, default: 0 },
  memoryXP: { type: Number, default: 0 },
  hangmanXP: { type: Number, default: 0 },
  gamesPlayed: { type: Number, default: 0 },
  lastUpdated: { type: Date, default: Date.now }
});
UserXPSchema.index({ userId: 1 });

// Game Score
const GameScoreSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  username: { type: String, required: true },
  gameType: { type: String, enum: ['quiz', 'math', 'memory', 'hangman'], required: true, index: true },
  score: { type: Number, required: true, default: 0 },
  xpEarned: { type: Number, required: true, default: 0 },
  difficulty: { type: String, enum: ['easy', 'medium', 'hard'], default: 'medium' },
  questionsAnswered: { type: Number, default: 0 },
  correctAnswers: { type: Number, default: 0 },
  timeTaken: { type: Number, default: 0 },
  playedAt: { type: Date, default: Date.now, index: true }
});
GameScoreSchema.index({ userId: 1, gameType: 1, playedAt: -1 });
GameScoreSchema.index({ gameType: 1, score: -1 });

// ========= ADD THIS AFTER UserBlockSchema =========
// Pending Notification Schema
const PendingNotificationSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['message', 'missed_call'], required: true },
  senderName: String,
  senderId: Types.ObjectId,
  senderAvatar: String,
  conversationId: String,
  content: String,
  callType: String,
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, expires: 604800 } // Auto-delete after 7 days
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
const PlannerTask = mongoose.model('PlannerTask', PlannerTaskSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);
const Message = mongoose.model('Message', MessageSchema);
const UserBlock = mongoose.model('UserBlock', UserBlockSchema);
const UserXP = mongoose.model('UserXP', UserXPSchema);
const GameScore = mongoose.model('GameScore', GameScoreSchema);
const Section = mongoose.model('Section', SectionSchema);
const GroupClass = mongoose.model('GroupClass', GroupClassSchema);
const GroupCallParticipant = mongoose.model('GroupCallParticipant', GroupCallParticipantSchema);
const ClassChatMessage = mongoose.model('ClassChatMessage', ClassChatMessageSchema);
const WhiteboardData = mongoose.model('WhiteboardData', WhiteboardDataSchema);

const PendingNotification = mongoose.model('PendingNotification', PendingNotificationSchema);

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
    
    io.to(userId.toString()).emit('new_notification', notification);
    return notification;
  } catch (error) {
    console.error('Notification creation error:', error);
  }
};

// ========= BLOCKING HELPER FUNCTIONS =========
async function isBlocked(blockerId, blockedId) {
  try {
    const block = await UserBlock.exists({ 
      blockerId, 
      blockedId 
    });
    return !!block;
  } catch (error) {
    console.error('isBlocked check error:', error);
    return false;
  }
}

async function getBlockedUserIds(userId) {
  try {
    const blocks = await UserBlock.find({ blockerId: userId })
      .select('blockedId')
      .lean();
    return blocks.map(b => b.blockedId.toString());
  } catch (error) {
    console.error('getBlockedUserIds error:', error);
    return [];
  }
}

// ========= WEBRTC HELPER FUNCTION =========
async function checkCallAuthorization(callerId, receiverId) {
  try {
    console.log(`🔍 Authorization check: Caller=${callerId}, Receiver=${receiverId}`);
    
    const caller = await User.findById(callerId);
    const receiver = await User.findById(receiverId);
    
    console.log(`👤 Caller: ${caller?.name} (${caller?.role})`);
    console.log(`👤 Receiver: ${receiver?.name} (${receiver?.role})`);
    
    if (!caller || !receiver) {
      console.log('❌ User not found');
      return false;
    }
    
    // Teacher calling student
    if (caller.role === 'TEACHER' && receiver.role === 'STUDENT') {
      const link = await TeacherStudentLink.findOne({
        teacherId: callerId,
        studentId: receiverId,
        isActive: true
      });
      console.log(`🔗 Teacher→Student link: ${link ? 'FOUND' : 'NOT FOUND'}`);
      return !!link;
    }
    
    // Student calling teacher
    if (caller.role === 'STUDENT' && receiver.role === 'TEACHER') {
      const link = await TeacherStudentLink.findOne({
        teacherId: receiverId,
        studentId: callerId,
        isActive: true
      });
      console.log(`🔗 Student→Teacher link: ${link ? 'FOUND' : 'NOT FOUND'}`);
      return !!link;
    }
    
    console.log('❌ Invalid role combination');
    return false;
  } catch (error) {
    console.error('❌ Authorization check error:', error);
    return false;
  }
}

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
// ========= SOCKET.IO FOR REAL-TIME =========
// ========= SOCKET.IO FOR REAL-TIME =========
const connectedUsers = new Map();
const activeCalls = new Map();
const onlineUsers = new Map();
const disconnectTimers = new Map();

io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);

  // Store active call sessions
  const activeCallSessions = new Map();
  let currentUserIdInCall = null;
  let currentSessionIdInCall = null;

  // ========= AUTHENTICATION & BASIC HANDLERS =========
  socket.on('authenticate', async (data) => {
    try {
      if (!data || !data.token) {
        socket.emit('auth_error', { error: 'Authentication token is required' });
        return;
      }

      const { token } = data;
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.sub).select('isActive role name email');
      
      if (!user) {
        socket.emit('auth_error', { error: 'User not found' });
        return;
      }
      
      if (!user.isActive) {
        socket.emit('auth_error', { error: 'Account is deactivated' });
        return;
      }

      socket.userId = decoded.sub;
      socket.role = decoded.role;
      socket.userEmail = decoded.email;
      
      const previousSocketId = connectedUsers.get(socket.userId);
      if (previousSocketId) {
        const previousSocket = io.sockets.sockets.get(previousSocketId);
        if (previousSocket && previousSocket.id !== socket.id) {
          previousSocket.emit('session_expired', { message: 'Logged in from another device' });
          previousSocket.disconnect(true);
        }
      }
      
      connectedUsers.set(socket.userId, socket.id);
      onlineUsers.set(socket.userId, socket.id);
      socket.join(socket.userId);
      
      await User.findByIdAndUpdate(socket.userId, {
        isOnline: true,
        lastSeen: new Date()
      });
      
      io.emit('user_online', { 
        userId: socket.userId,
        userInfo: {
          name: user.name,
          role: user.role,
          email: user.email
        }
      });
      
      socket.emit('authenticated', { 
        success: true,
        user: {
          id: socket.userId,
          name: user.name,
          email: user.email,
          role: user.role
        }
      });
      
    } catch (error) {
      console.error('❌ Authentication error:', error.message);
      let errorMessage = 'Authentication failed';
      if (error.name === 'JsonWebTokenError') {
        errorMessage = 'Invalid token';
      } else if (error.name === 'TokenExpiredError') {
        errorMessage = 'Token expired';
      }
      
      socket.emit('auth_error', { 
        error: errorMessage,
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  });

  socket.on('request_pending_notifications', async () => {
    try {
      const userId = socket.userId;
      if (!userId) {
        console.log('❌ No userId - cannot fetch pending notifications');
        return;
      }
      
      const notifications = await PendingNotification.find({
        userId: userId,
        read: false
      }).sort({ createdAt: -1 }).limit(50);
      
      console.log(`📬 Found ${notifications.length} pending notifications for user ${userId}`);
      
      const formattedNotifications = notifications.map(notif => ({
        type: notif.type,
        senderName: notif.senderName,
        senderId: notif.senderId,
        senderAvatar: notif.senderAvatar,
        conversationId: notif.conversationId,
        content: notif.content,
        callType: notif.callType,
        createdAt: notif.createdAt
      }));
      
      socket.emit('pending_notifications', {
        notifications: formattedNotifications
      });
      
      await PendingNotification.updateMany(
        { userId: userId, read: false },
        { $set: { read: true } }
      );
      
      console.log(`✅ Sent ${notifications.length} pending notifications`);
    } catch (error) {
      console.error('❌ Error fetching pending notifications:', error);
    }
  });

  socket.on('join_conversation', async (conversationId) => {
    if (!socket.userId) {
      socket.emit('error', { error: 'Authentication required' });
      return;
    }
    socket.join(`conversation_${conversationId}`);
    
    // ✅ MARK UNDELIVERED MESSAGES AS DELIVERED (single tick → double tick)
    try {
      const undeliveredMessages = await Message.find({
        conversationId: conversationId,
        receiverId: socket.userId,
        delivered: false
      });
      
      if (undeliveredMessages.length > 0) {
        await Message.updateMany(
          {
            conversationId: conversationId,
            receiverId: socket.userId,
            delivered: false
          },
          {
            $set: {
              delivered: true,
              deliveredAt: new Date()
            }
          }
        );
        
        undeliveredMessages.forEach(msg => {
          io.to(`conversation_${conversationId}`).emit('message_delivered', {
            messageId: msg._id.toString()
          });
        });
        
        console.log(`✅ Marked ${undeliveredMessages.length} messages as delivered`);
      }
    } catch (error) {
      console.error('Error marking messages as delivered:', error);
    }
  });

  socket.on('leave_conversation', (conversationId) => {
    socket.leave(`conversation_${conversationId}`);
  });

  socket.on('send_message', async (data) => {
  try {
    const { 
      conversationId, 
      receiverId, 
      content, 
      type, 
      iv, 
      tempId, 
      replyTo,
      fileUrl,
      fileName,
      fileSize,
      mimeType,
      duration
    } = data;
    
    if (!socket.userId) {
      socket.emit('message_error', { error: 'Not authenticated', tempId });
      return;
    }

    // Check if blocked
    const blocked = await isBlocked(receiverId, socket.userId);
    if (blocked) {
      console.log(`🚫 Message blocked: ${socket.userId} -> ${receiverId}`);
      socket.emit('message_sent', { tempId, messageId: Date.now().toString() });
      return;
    }

    if (!conversationId || !receiverId || !content) {
      socket.emit('message_error', { error: 'Missing required fields', tempId });
      return;
    }

    // Get sender info for relay
    const sender = await User.findById(socket.userId).select('name avatar role');
    
    // Generate a message ID for tracking
    const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Build message payload for relay (NO MongoDB save)
    const messagePayload = {
      id: messageId,
      _id: messageId,
      conversationId,
      senderId: {
        _id: socket.userId,
        id: socket.userId,
        name: sender.name,
        avatar: sender.avatar,
        role: sender.role
      },
      receiverId,
      content,
      type: type || 'TEXT',
      fileUrl: fileUrl || null,
      fileName: fileName || null,
      fileSize: fileSize || null,
      mimeType: mimeType || null,
      duration: duration || null,
      iv,
      replyTo: replyTo || null,
      delivered: false,
      read: false,
      createdAt: new Date().toISOString()
    };

    // Check if receiver is online
    const receiverSocketId = connectedUsers.get(receiverId.toString());
    const receiverSocket = receiverSocketId ? io.sockets.sockets.get(receiverSocketId) : null;
    const isReceiverOnline = receiverSocket && receiverSocket.connected;

    if (isReceiverOnline) {
      // Receiver is online - relay message directly
      messagePayload.delivered = true;
      messagePayload.deliveredAt = new Date().toISOString();
      
      // Emit to conversation room
      io.to(`conversation_${conversationId}`).emit('new_message', messagePayload);
      
      // Also emit to receiver's personal room
      io.to(receiverId.toString()).emit('new_message', messagePayload);
      
      // Emit delivery confirmation
      io.to(`conversation_${conversationId}`).emit('message_delivered', {
        messageId: messageId
      });
      
      console.log(`✅ Message relayed (online): ${messageId}`);
    } else {
      // Receiver is offline - just emit to conversation room
      // The receiver will get the message when they come online (from their local DB)
      io.to(`conversation_${conversationId}`).emit('new_message', messagePayload);
      
      // Store minimal notification for offline user
      await PendingNotification.create({
        userId: receiverId,
        type: 'message',
        senderName: sender.name,
        senderId: socket.userId,
        senderAvatar: sender.avatar,
        conversationId: conversationId,
        content: content.substring(0, 100)
      });
      
      console.log(`📧 Message relayed, notification stored for offline user ${receiverId}`);
    }

    // Confirm to sender
    socket.emit('message_sent', { 
      tempId, 
      messageId: messageId 
    });

  } catch (error) {
    console.error('❌ Send message error:', error);
    socket.emit('message_error', { 
      error: 'Failed to send message', 
      tempId: data.tempId 
    });
  }
});

  socket.on('mark_read', async (data) => {
  try {
    const { messageId, conversationId } = data;
    
    if (!socket.userId) return;

    // Just relay the read receipt - no MongoDB update
    io.to(`conversation_${conversationId}`).emit('message_read', { 
      messageId,
      readBy: socket.userId,
      readAt: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Mark read error:', error);
  }
});

  // Mark all messages in a conversation as read (for notification "Mark as Read" button)
socket.on('mark_all_read', async (data) => {
  try {
    const { conversationId } = data;
    
    if (!socket.userId) return;
    
    console.log(`📖 Marking all messages as read in conversation: ${conversationId}`);
    
    // Just relay the read receipt - no MongoDB update
    io.to(`conversation_${conversationId}`).emit('all_messages_read', {
      conversationId,
      readBy: socket.userId,
      readAt: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Mark all read error:', error);
  }
});

  socket.on('delete_message', async (data) => {
  try {
    const { messageId, conversationId, deleteForEveryone } = data;
    
    if (!socket.userId) return;
    
    // Get sender info for proper authorization check
    const sender = await User.findById(socket.userId).select('name');
    
    // 🚀 Enhanced deletion relay with full context
    const deletionData = {
      messageId,
      conversationId,
      deletedBy: socket.userId,
      deletedByName: sender.name,
      deleteForEveryone: deleteForEveryone || false,
      deletedAt: new Date().toISOString()
    };
    
    // Relay deletion to all participants in conversation
    io.to(`conversation_${conversationId}`).emit('message_deleted', deletionData);
    
    // Also emit to both users' personal rooms for offline handling
    socket.emit('message_deletion_confirmed', { messageId, deleteForEveryone });
    
    console.log(`🗑️ Message deletion relayed: ${messageId} (deleteForEveryone: ${deleteForEveryone})`);
    
  } catch (error) {
    console.error('❌ Delete message error:', error);
    socket.emit('message_deletion_failed', { 
      messageId: data.messageId, 
      error: 'Failed to delete message' 
    });
  }
});

  socket.on('user_online', async () => {
    if (socket.userId) {
      await User.findByIdAndUpdate(socket.userId, {
        isOnline: true,
        lastSeen: new Date()
      });
      io.emit('user_online', { userId: socket.userId });
    }
  });

  socket.on('user_offline', async () => {
    if (socket.userId) {
      const lastSeen = new Date();
      await User.findByIdAndUpdate(socket.userId, {
        isOnline: false,
        lastSeen: lastSeen
      });
      io.emit('user_offline', { 
        userId: socket.userId,
        lastSeen: lastSeen.toISOString()
      });
    }
  });

  socket.on('typing', (data) => {
    const { conversationId, receiverId } = data;
    if (!socket.userId) return;
    
    // ✅ FIX: Emit to conversation room
    io.to(`conversation_${conversationId}`).emit('user_typing', { 
      conversationId, 
      userId: socket.userId 
    });
  });

  socket.on('stop_typing', (data) => {
    const { conversationId, receiverId } = data;
    if (!socket.userId) return;
    
    // ✅ FIX: Emit to conversation room
    io.to(`conversation_${conversationId}`).emit('user_stop_typing', { 
      conversationId, 
      userId: socket.userId 
    });
  });

  // ========= WEBRTC SIGNALING FOR VOICE/VIDEO CALLS =========
  // ========= WEBRTC SIGNALING FOR VOICE/VIDEO CALLS =========
socket.on('call-user', async (data) => {
  try {
    const { receiverId, callType, offer, conversationId } = data;  // ✅ ADD conversationId
    const callerId = socket.userId;
    
    if (!callerId || !receiverId) {
      socket.emit('call-error', { error: 'Invalid call data' });
      return;
    }

    // Check if blocked
    const blocked = await isBlocked(receiverId, callerId);
    if (blocked) {
      console.log(`🚫 Call blocked: ${callerId} -> ${receiverId}`);
      socket.emit('call-error', { error: 'User is unavailable' });
      return;
    }
    
    // Check authorization (teacher-student link)
    const isAuthorized = await checkCallAuthorization(callerId, receiverId);
    if (!isAuthorized) {
      socket.emit('call-error', { error: 'Not authorized' });
      return;
    }
    
    // Get caller info
    const caller = await User.findById(callerId).select('name avatar');
    
    // Find receiver's socket
    const receiverSocketId = onlineUsers.get(receiverId);
    
    // ✅ FIX: Verify socket is actually connected (not stale)
    const receiverSocket = receiverSocketId ? io.sockets.sockets.get(receiverSocketId) : null;
    
    if (!receiverSocket || !receiverSocket.connected) {
      console.log(`📞 Receiver ${receiverId} socket is stale/offline`);
      
      // ✅ Clean up stale socket from map
      if (receiverSocketId) {
        onlineUsers.delete(receiverId);
        connectedUsers.delete(receiverId);
      }
      
      // Store missed call for offline user
      await PendingNotification.create({
        userId: receiverId,
        type: 'missed_call',
        senderName: caller.name,
        senderId: callerId,
        senderAvatar: caller.avatar,
        conversationId: conversationId || '',
        callType: callType === 'video' ? 'video call' : 'voice call',
        content: `Missed ${callType === 'video' ? 'video' : 'voice'} call`
      });
      
      socket.emit('call-error', { error: 'User offline' });
      return;
    }
    
    console.log(`📞 Sending call to ${receiverId} (socket: ${receiverSocketId})`);
    
    // ✅ FIX: Include conversationId in call-made event
    receiverSocket.emit('call-made', {
      callerId: callerId,
      callerName: caller.name,
      callerAvatar: caller.avatar,
      callType: callType,
      offer: offer,
      conversationId: conversationId || ''  // ✅ ADD THIS
    });
    
    // Notify caller that call is ringing
    socket.emit('call-ringing');
    
    console.log(`✅ Call notification sent to ${receiverId}`);
    
  } catch (error) {
    console.error('Call user error:', error);
    socket.emit('call-error', { error: 'Failed to initiate call' });
  }
});
  
  // Answer call
  socket.on('answer-call', async (data) => {
    try {
      const { callerId, answer } = data;
      const callerSocketId = onlineUsers.get(callerId);
      
      if (callerSocketId) {
        io.to(callerSocketId).emit('call-answered', { answer });
      }
    } catch (error) {
      console.error('Answer call error:', error);
    }
  });
  
  // Reject call
  socket.on('reject-call', async (data) => {
    try {
      const { callerId } = data;
      const callerSocketId = onlineUsers.get(callerId);
      
      if (callerSocketId) {
        io.to(callerSocketId).emit('call-rejected');
      }
    } catch (error) {
      console.error('Reject call error:', error);
    }
  });
  
  // End call
  socket.on('end-call', async (data) => {
    try {
      const { targetUserId } = data;
      const targetSocketId = onlineUsers.get(targetUserId);
      
      if (targetSocketId) {
        io.to(targetSocketId).emit('call-ended');
      }
    } catch (error) {
      console.error('End call error:', error);
    }
  });
  
  // ICE candidate exchange
  socket.on('ice-candidate', async (data) => {
    try {
      const { targetUserId, candidate } = data;
      const targetSocketId = onlineUsers.get(targetUserId);
      
      if (targetSocketId) {
        io.to(targetSocketId).emit('ice-candidate', { candidate });
      }
    } catch (error) {
      console.error('ICE candidate error:', error);
    }
  });

  // ========= ADD CALL NOTIFICATION HANDLER RIGHT HERE =========
  socket.on('call-not-answered', async (data) => {
    try {
      const { callerId, receiverId, isVideo, conversationId } = data;
      const receiverSocketId = onlineUsers.get(receiverId);
      
      if (!receiverSocketId) {
        const caller = await User.findById(callerId);
        await PendingNotification.create({
          userId: receiverId,
          type: 'missed_call',
          senderName: caller.name,
          senderId: callerId,
          senderAvatar: caller.avatar,
          conversationId: conversationId,
          callType: isVideo ? 'video call' : 'voice call',
          content: `Missed ${isVideo ? 'video' : 'voice'} call`
        });
        console.log(`📞 Stored missed call notification for OFFLINE user ${receiverId}`);
      }
    } catch (error) {
      console.error('❌ Error storing missed call:', error);
    }
  });

  // ========= GROUP CALL HANDLERS =========
  
  // Join group call
  socket.on('join-group-call', async (data) => {
    try {
      const payload = typeof data === 'string' ? JSON.parse(data) : data;
      const { sessionId, userId, userName, role, isVideoEnabled, isAudioEnabled } = payload;

      // ✅ ADD THESE LINES:
      // Cancel pending disconnect if user is rejoining
      if (disconnectTimers.has(userId)) {
        clearTimeout(disconnectTimers.get(userId));
        disconnectTimers.delete(userId);
        console.log(`✅ ${userName} reconnected before timeout, canceling disconnect`);
      }

      console.log(`📞 ${userName} joining ${sessionId}`);

      // Store info on socket
      socket.callSessionId = sessionId;
      socket.callUserId = userId;
      socket.callUserName = userName;
      socket.callRole = role;

      // Join room
      socket.join(sessionId);

      // Update class status if host
      if (role === 'HOST') {
        await GroupClass.findOneAndUpdate(
          { sessionId },
          { status: 'LIVE', startedAt: new Date() }
        );
      }

      // Get all sockets in this room to send participant list
      const socketsInRoom = await io.in(sessionId).fetchSockets();
      const participants = socketsInRoom
        .filter(s => s.id !== socket.id && s.callUserId) // Exclude self
        .map(s => ({
          userId: s.callUserId,
          name: s.callUserName,
          role: s.callRole,
          isVideoEnabled: false, // Client will update
          isAudioEnabled: false
        }));

      // Check if host is present
      const hostJoined = socketsInRoom.some(s => s.callRole === 'HOST');

      // Send existing participants to new user
      socket.emit('existing-participants', {
        participants,
        hostJoined
      });

      // Notify others about new participant
      socket.to(sessionId).emit('participant-joined', {
        userId,
        name: userName,
        role,
        isVideoEnabled: isVideoEnabled || false,
        isAudioEnabled: isAudioEnabled || false
      });

      console.log(`✅ ${userName} joined, sent ${participants.length} existing participants`);

    } catch (error) {
      console.error('Join error:', error);
      socket.emit('group-call-error', { message: error.message });
    }
  });

  // Leave group call
  socket.on('leave-group-call', async (data) => {
    try {
      const { sessionId, userId } = typeof data === 'string' ? JSON.parse(data) : data;
      const wasHost = socket.callRole === 'HOST';
      
      console.log(`👋 ${userId} leaving ${sessionId}`);
      
      socket.leave(sessionId);
      
      // Notify others
      socket.to(sessionId).emit('participant-left', { userId });
      
      // If host left, notify room
      if (wasHost) {
        socket.to(sessionId).emit('host-left', {
          message: 'Host has left the call'
        });
      }
      
      socket.callSessionId = null;
      socket.callUserId = null;

    } catch (error) {
      console.error('Leave error:', error);
    }
  });

  // End call (host only)
  socket.on('end-group-call', async (data) => {
    try {
      const { sessionId } = typeof data === 'string' ? JSON.parse(data) : data;

      if (socket.callRole !== 'HOST') {
        socket.emit('group-call-error', { message: 'Only host can end call' });
        return;
      }

      console.log(`🛑 Host ending ${sessionId}`);

      // Update class status
      await GroupClass.findOneAndUpdate(
        { sessionId },
        { status: 'COMPLETED', endedAt: new Date() }
      );

      // Notify all participants
      io.to(sessionId).emit('call-ended-by-host', {
        message: 'Class ended by teacher'
      });

      console.log(`✅ Call ${sessionId} ended by host`);

    } catch (error) {
      console.error('End call error:', error);
    }
  });

  // WebRTC Offer - relay to target
  socket.on('webrtc-offer', async (data) => {
    try {
      const { sessionId, targetUserId, offer } = typeof data === 'string' ? JSON.parse(data) : data;
      
      // Find target socket in room
      const socketsInRoom = await io.in(sessionId).fetchSockets();
      const targetSocket = socketsInRoom.find(s => s.callUserId === targetUserId);
      
      if (targetSocket) {
        targetSocket.emit('webrtc-offer', {
          fromUserId: socket.callUserId,
          offer
        });
      }
    } catch (error) {
      console.error('Offer error:', error);
    }
  });

  // WebRTC Answer - relay to target
  socket.on('webrtc-answer', async (data) => {
    try {
      const { sessionId, targetUserId, answer } = typeof data === 'string' ? JSON.parse(data) : data;
      
      const socketsInRoom = await io.in(sessionId).fetchSockets();
      const targetSocket = socketsInRoom.find(s => s.callUserId === targetUserId);
      
      if (targetSocket) {
        targetSocket.emit('webrtc-answer', {
          fromUserId: socket.callUserId,
          answer
        });
      }
    } catch (error) {
      console.error('Answer error:', error);
    }
  });

  // ICE Candidate - relay to target
  socket.on('webrtc-ice-candidate', async (data) => {
    try {
      const { sessionId, targetUserId, candidate } = typeof data === 'string' ? JSON.parse(data) : data;
      
      const socketsInRoom = await io.in(sessionId).fetchSockets();
      const targetSocket = socketsInRoom.find(s => s.callUserId === targetUserId);
      
      if (targetSocket) {
        targetSocket.emit('webrtc-ice-candidate', {
          fromUserId: socket.callUserId,
          candidate
        });
      }
    } catch (error) {
      console.error('ICE error:', error);
    }
  });

  // Toggle Audio - broadcast to room
  // Toggle Audio - broadcast to room
socket.on('toggle-audio', (data) => {
  try {
    const { sessionId, userId, isAudioEnabled } = typeof data === 'string' ? JSON.parse(data) : data;
    
    // ✅ FIX: Broadcast BOTH events
    socket.to(sessionId).emit('toggle-audio', {
      userId,
      isAudioEnabled
    });
    
    socket.to(sessionId).emit('media-state-changed', {
      userId,
      isAudioEnabled
    });
  } catch (error) {
    console.error('Toggle audio error:', error);
  }
});

  // Toggle Video - broadcast to room
  // Toggle Video - broadcast to room
socket.on('toggle-video', (data) => {
  try {
    const { sessionId, userId, isVideoEnabled } = typeof data === 'string' ? JSON.parse(data) : data;
    
    // ✅ FIX: Broadcast BOTH events
    socket.to(sessionId).emit('toggle-video', {
      userId,
      isVideoEnabled
    });
    
    socket.to(sessionId).emit('media-state-changed', {
      userId,
      isVideoEnabled
    });
  } catch (error) {
    console.error('Toggle video error:', error);
  }
});

  // Start Screen Share - broadcast to room
  socket.on('start-screen-share', (data) => {
    try {
      const { sessionId, userId } = typeof data === 'string' ? JSON.parse(data) : data;
      socket.to(sessionId).emit('screen-share-started', { userId });
    } catch (error) {
      console.error('Screen share error:', error);
    }
  });

  // Stop Screen Share - broadcast to room
  socket.on('stop-screen-share', (data) => {
    try {
      const { sessionId, userId } = typeof data === 'string' ? JSON.parse(data) : data;
      socket.to(sessionId).emit('screen-share-stopped', { userId });
    } catch (error) {
      console.error('Stop screen share error:', error);
    }
  });

  // Raise Hand - broadcast to room
  socket.on('raise-hand', (data) => {
    try {
      const { sessionId, userId } = typeof data === 'string' ? JSON.parse(data) : data;
      socket.to(sessionId).emit('hand-raised', { userId });
    } catch (error) {
      console.error('Raise hand error:', error);
    }
  });

  // Lower Hand - broadcast to room
  socket.on('lower-hand', (data) => {
    try {
      const { sessionId, userId } = typeof data === 'string' ? JSON.parse(data) : data;
      socket.to(sessionId).emit('hand-lowered', { userId });
    } catch (error) {
      console.error('Lower hand error:', error);
    }
  });

  // Class Chat - broadcast to room
  socket.on('class-chat-message', async (data) => {
    try {
      const payload = typeof data === 'string' ? JSON.parse(data) : data;
      const { sessionId, userId, userName, message, timestamp } = payload;

      // Optionally save to DB
      await ClassChatMessage.create({
        sessionId,
        senderId: userId,
        senderName: userName,
        message,
        type: 'TEXT',
        isPrivate: false
      });

      // Broadcast to room (including sender for confirmation)
      io.to(sessionId).emit('class-chat-message', {
        userId,
        userName,
        message,
        timestamp: timestamp || Date.now()
      });
    } catch (error) {
      console.error('Chat error:', error);
    }
  });

  // Whiteboard Draw - broadcast to room
  socket.on('whiteboard-draw', async (data) => {
    try {
      const payload = typeof data === 'string' ? JSON.parse(data) : data;
      const { sessionId, userId, strokeData } = payload;

      // Optionally save to DB
      let whiteboard = await WhiteboardData.findOne({ sessionId });
      if (!whiteboard) {
        whiteboard = await WhiteboardData.create({
          sessionId,
          strokes: [],
          images: []
        });
      }
      whiteboard.strokes.push(strokeData);
      await whiteboard.save();

      // Broadcast to others (not sender)
      socket.to(sessionId).emit('whiteboard-draw', {
        userId,
        strokeData
      });
    } catch (error) {
      console.error('Whiteboard draw error:', error);
    }
  });

  // Whiteboard Clear - broadcast to room
  socket.on('whiteboard-clear', async (data) => {
    try {
      const payload = typeof data === 'string' ? JSON.parse(data) : data;
      const { sessionId, userId } = payload;

      // Clear in DB
      await WhiteboardData.findOneAndUpdate(
        { sessionId },
        { strokes: [], images: [], updatedAt: new Date() },
        { upsert: true }
      );

      // Broadcast to all
      io.to(sessionId).emit('whiteboard-clear', { userId });
    } catch (error) {
      console.error('Whiteboard clear error:', error);
    }
  });

  // ========= DISCONNECT HANDLER =========
  socket.on('disconnect', async (reason) => {
    console.log(`🔌 User disconnected: ${socket.id}, Reason: ${reason}`);
    
    // 1-on-1 call cleanup
    if (socket.userId && activeCalls.has(socket.userId)) {
      const otherUserId = activeCalls.get(socket.userId);
      activeCalls.delete(socket.userId);
      if (otherUserId) {
        activeCalls.delete(otherUserId);
        const otherSocketId = connectedUsers.get(otherUserId);
        if (otherSocketId) {
          io.to(otherSocketId).emit('call-ended', { userId: socket.userId, reason: 'disconnected' });
        }
      }
    }
    
    // User online status cleanup
    if (socket.userId) {
      connectedUsers.delete(socket.userId);
      onlineUsers.delete(socket.userId);
      const lastSeen = new Date();
      await User.findByIdAndUpdate(socket.userId, {
        isOnline: false,
        lastSeen: lastSeen
      });
      
      // ✅ FIX: Only broadcast to conversation partners, not everyone
      try {
        const conversations = await Conversation.find({
          $or: [
            { teacherId: socket.userId },
            { studentId: socket.userId }
          ]
        }).lean();
        
        // Notify each conversation partner individually
        for (const conv of conversations) {
          const partnerId = conv.teacherId.toString() === socket.userId 
            ? conv.studentId.toString() 
            : conv.teacherId.toString();
          
          io.to(partnerId).emit('user_offline', { 
            userId: socket.userId,
            lastSeen: lastSeen.toISOString()
          });
        }
        
        console.log(`📴 User ${socket.userId} offline status sent to ${conversations.length} partners`);
      } catch (error) {
        console.error('Error broadcasting offline status:', error);
      }
    }

    // ========= GROUP CALL CLEANUP WITH GRACE PERIOD =========
    if (socket.callSessionId && socket.callUserId) {
      const sessionId = socket.callSessionId;
      const userId = socket.callUserId;
      const userName = socket.callUserName || userId; // ✅ ADD THIS LINE
      const wasHost = socket.callRole === 'HOST';
      
      console.log(`⏳ ${userName} disconnected from ${sessionId}, waiting 10s for reconnection...`);
      
      // ✅ Wait 10 seconds before marking as left
      const timerId = setTimeout(() => {
        console.log(`🔴 ${userId} did not reconnect, marking as left`);
        
        // Notify room
        if (wasHost) {
          io.to(sessionId).emit('host-left', {
            userId: userId, // ✅ ADD THIS LINE
            message: 'Host has disconnected'
          });
        }
        
        io.to(sessionId).emit('participant-left', { userId });
        
        // Clean up timer
        disconnectTimers.delete(userId);
      }, 10000); // 10 second grace period
      
      // Store timer so we can cancel it if user reconnects
      disconnectTimers.set(userId, timerId);
    }
  });

  socket.on('error', (error) => {
    console.error('❌ Socket error:', error);
  });

}); // ← END OF io.on('connection')
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
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
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

app.delete('/api/auth/account', authRequired, async (req, res) => {
  try {
    const userId = req.userId;
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const role = user.role;

    if (role === 'TEACHER') {
      await TeacherStudentLink.deleteMany({ teacherId: userId });
      await ClassModel.deleteMany({ teacherId: userId });
      const teacherAssignments = await Assignment.find({ teacherId: userId });
      const assignmentIds = teacherAssignments.map(a => a._id);
      await AssignmentSubmission.deleteMany({ assignmentId: { $in: assignmentIds } });
      await Assignment.deleteMany({ teacherId: userId });
      await Note.deleteMany({ teacherId: userId });
      await Exam.deleteMany({ teacherId: userId });
      await Result.deleteMany({ teacherId: userId });
      await Attendance.deleteMany({ teacherId: userId });
    } else if (role === 'STUDENT') {
      await TeacherStudentLink.deleteMany({ studentId: userId });
      await AssignmentSubmission.deleteMany({ studentId: userId });
      await Result.deleteMany({ studentId: userId });
      await Attendance.updateMany(
        {},
        { $pull: { marks: { studentId: userId } } }
      );
    }

    await Notification.deleteMany({ userId });
    await User.findByIdAndDelete(userId);

    console.log(`✅ Account deleted: ${user.email} (${role})`);
    res.status(204).send();
  } catch (error) {
    console.error('Account deletion error:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// ========= TEACHER-STUDENT LINK ENDPOINTS =========
// POST /api/teacher/link-student - Link a student using their code
app.post('/api/teacher/link-student', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Student code is required' });
    }

    // Find the student by code
    const student = await User.findOne({ 
      studentCode: code, 
      role: 'STUDENT', 
      isActive: true 
    });

    if (!student) {
      return res.status(404).json({ error: 'Student not found with this code' });
    }

    // ✅ NEW: Check if student has BLOCKED this teacher
    const blockedLink = await TeacherStudentLink.findOne({
      teacherId: req.userId,
      studentId: student._id,
      isBlocked: true
    });

    if (blockedLink) {
      return res.status(403).json({ 
        error: 'This student has blocked you. They must unblock you first.' 
      });
    }

    // Check if already linked and active
    const existingLink = await TeacherStudentLink.findOne({
      teacherId: req.userId,
      studentId: student._id,
      isActive: true
    });

    if (existingLink) {
      return res.status(200).json({ 
        success: true, 
        message: 'Student is already linked to your account' 
      });
    }

    // Check if there's a deactivated (unlinked) link
    const deactivatedLink = await TeacherStudentLink.findOne({
      teacherId: req.userId,
      studentId: student._id,
      isActive: false
    });

    if (deactivatedLink) {
      // Re-activate the existing link
      deactivatedLink.isActive = true;
      deactivatedLink.linkedAt = new Date();
      await deactivatedLink.save();
    } else {
      // Create new link
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

app.get('/api/teacher/students', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;

    const links = await TeacherStudentLink.find({ 
      teacherId, 
      isActive: true 
    }).populate('studentId', 'name email mobile studentCode');

    const students = links
      .filter(link => link.studentId)
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

// ========= TEACHER RANKINGS ENDPOINT =========

// GET /api/teacher/rankings
app.get('/api/teacher/rankings', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;

    // Get all results for this teacher
    const results = await Result.find({
      teacherId: teacherId,
      published: true
    })
    .populate('studentId', 'name studentCode')
    .populate('examId')
    .sort({ publishedAt: -1 })
    .lean();

    if (!results || results.length === 0) {
      return res.json({
        success: true,
        rankings: []
      });
    }

    // Group results by exam
    const examGroups = {};
    results.forEach(result => {
      const examKey = result.examId?._id?.toString() || result.examTitle;
      
      if (!examGroups[examKey]) {
        examGroups[examKey] = {
          examTitle: result.examTitle,
          subject: result.subject || 'General',
          date: result.publishedAt || result.createdAt,
          results: []
        };
      }
      
      examGroups[examKey].results.push({
        studentId: result.studentId?._id?.toString() || '',
        studentName: result.studentId?.name || 'Unknown Student',
        studentCode: result.studentId?.studentCode || null,
        obtainedMarks: result.obtainedMarks,
        totalMarks: result.totalMarks,
        percentage: result.percentage || ((result.obtainedMarks / result.totalMarks) * 100),
        grade: result.grade || calculateGrade((result.obtainedMarks / result.totalMarks) * 100)
      });
    });

    // Process each exam group into ranking format
    const rankings = Object.values(examGroups).map(examGroup => {
      // Sort students by percentage (descending)
      const sortedResults = examGroup.results.sort((a, b) => b.percentage - a.percentage);
      
      // Assign ranks
      let currentRank = 1;
      const rankedStudents = sortedResults.map((student, index) => {
        // Handle ties - same percentage gets same rank
        if (index > 0 && student.percentage < sortedResults[index - 1].percentage) {
          currentRank = index + 1;
        }
        
        return {
          rank: currentRank,
          studentId: student.studentId,
          studentName: student.studentName,
          studentCode: student.studentCode,
          obtainedMarks: parseFloat(student.obtainedMarks),
          totalMarks: parseFloat(student.totalMarks),
          percentage: parseFloat(student.percentage.toFixed(2)),
          grade: student.grade
        };
      });

      // Calculate statistics
      const totalStudents = rankedStudents.length;
      const topPerformer = rankedStudents.length > 0 ? rankedStudents[0].studentName : null;
      const averagePercentage = totalStudents > 0
        ? parseFloat((rankedStudents.reduce((sum, s) => sum + s.percentage, 0) / totalStudents).toFixed(2))
        : 0;

      return {
        examTitle: examGroup.examTitle,
        subject: examGroup.subject,
        date: examGroup.date.toISOString(),
        totalStudents: totalStudents,
        topPerformer: topPerformer,
        averagePercentage: averagePercentage,
        rankings: rankedStudents
      };
    });

    res.json({
      success: true,
      rankings: rankings
    });

  } catch (error) {
    console.error('Teacher rankings error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch rankings',
      rankings: []
    });
  }
});

// ========= STUDENT RANKINGS ENDPOINT =========
// GET /api/student/rankings - Get rankings for student across all their teachers
app.get('/api/student/rankings', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;

    // Get all linked teachers
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({
        success: true,
        rankings: []
      });
    }

    // Get all results for this student from all their teachers
    const results = await Result.find({
      teacherId: { $in: linkedTeacherIds },
      studentId: studentId,
      published: true
    })
    .populate('teacherId', 'name')
    .populate('examId')
    .sort({ publishedAt: -1 })
    .lean();

    if (!results || results.length === 0) {
      return res.json({
        success: true,
        rankings: []
      });
    }

    // Group results by teacher and exam
    const teacherRankingsMap = {};
    
    for (const result of results) {
      const teacherId = result.teacherId._id.toString();
      const teacherName = result.teacherId.name;
      
      if (!teacherRankingsMap[teacherId]) {
        teacherRankingsMap[teacherId] = {
          teacherId: teacherId,
          teacherName: teacherName,
          exams: []
        };
      }
      
      // Get all results for this exam to determine ranking
      const examKey = result.examId?._id?.toString() || result.examTitle;
      const allExamResults = await Result.find({
        teacherId: teacherId,
        $or: [
          { examId: result.examId },
          { examTitle: result.examTitle, subject: result.subject }
        ],
        published: true
      })
      .populate('studentId', 'name studentCode')
      .sort({ obtainedMarks: -1, percentage: -1 })
      .lean();
      
      // Calculate rankings
      const sortedResults = allExamResults
        .map(r => ({
          studentId: r.studentId?._id?.toString() || '',
          studentName: r.studentId?.name || 'Unknown',
          obtainedMarks: parseFloat(r.obtainedMarks),
          totalMarks: parseFloat(r.totalMarks),
          percentage: parseFloat(r.percentage || ((r.obtainedMarks / r.totalMarks) * 100)),
          grade: r.grade || calculateGrade((r.obtainedMarks / r.totalMarks) * 100)
        }))
        .sort((a, b) => b.percentage - a.percentage);
      
      // Assign ranks
      let currentRank = 1;
      const rankedStudents = sortedResults.map((student, index) => {
        if (index > 0 && student.percentage < sortedResults[index - 1].percentage) {
          currentRank = index + 1;
        }
        return {
          rank: currentRank,
          studentId: student.studentId,
          studentName: student.studentName,
          obtainedMarks: student.obtainedMarks,
          totalMarks: student.totalMarks,
          percentage: parseFloat(student.percentage.toFixed(2)),
          grade: student.grade,
          isCurrentStudent: student.studentId === studentId.toString()
        };
      });
      
      // Find current student's rank
      const myRanking = rankedStudents.find(r => r.isCurrentStudent);
      
      teacherRankingsMap[teacherId].exams.push({
        examTitle: result.examTitle,
        subject: result.subject || 'General',
        date: result.publishedAt || result.createdAt,
        totalStudents: rankedStudents.length,
        rankings: rankedStudents
      });
    }

    // Convert map to array
    const rankings = Object.values(teacherRankingsMap);

    res.json({
      success: true,
      rankings: rankings
    });

  } catch (error) {
    console.error('Student rankings error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch rankings',
      rankings: []
    });
  }
});

app.delete('/api/teacher/students/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const studentId = req.params.id;
    const teacherId = req.userId;

    const result = await TeacherStudentLink.findOneAndUpdate(
      { teacherId, studentId, isActive: true },
      { isActive: false, unlinkedAt: new Date() },
      { new: true }
    );

    if (!result) {
      return res.status(404).json({ error: 'Student link not found' });
    }

    const teacher = await User.findById(teacherId);
    await createNotification(
      studentId,
      'SYSTEM',
      'Teacher Disconnected',
      `${teacher.name} has removed you from their student list`,
      { teacherId }
    );

    console.log(`✅ Teacher ${teacher.email} unlinked student ${studentId}`);
    res.status(204).send();
  } catch (error) {
    console.error('Unlink student error:', error);
    res.status(500).json({ error: 'Failed to unlink student' });
  }
});

// ========= STUDENT ENDPOINTS =========
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
    // ✅ Get ALL links (active AND blocked) so student can unblock
    const links = await TeacherStudentLink.find({ 
      studentId: req.userId
      // Removed isActive filter - show blocked teachers too!
    })
    .populate('teacherId', 'name email mobile avatar')
    .lean();

    const teachers = links
      .filter(link => link.teacherId) // Only filter out null teachers
      .map(link => ({
        id: link.teacherId._id.toString(),
        name: link.teacherId.name,
        email: link.teacherId.email,
        mobile: link.teacherId.mobile,
        avatar: link.teacherId.avatar,
        linkedDate: link.linkedAt,
        isBlocked: link.isBlocked || false  // ✅ Show block status
      }));

    res.json({ success: true, teachers });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch teachers' });
  }
});

// ========= STUDENT TEACHER MANAGEMENT (UNLINK/BLOCK/UNBLOCK) =========

// POST /api/student/teachers/:teacherId/unlink
app.post('/api/student/teachers/:teacherId/unlink', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const teacherId = req.params.teacherId;
    
    // Find the link
    const link = await TeacherStudentLink.findOne({
      teacherId: teacherId,
      studentId: studentId
    });
    
    if (!link) {
      return res.status(404).json({ 
        success: false,
        error: 'Teacher link not found' 
      });
    }
    
    // Unlink: Deactivate the link (teacher can re-add student later)
    link.isActive = false;
    link.unlinkedAt = new Date();
    await link.save();
    
    console.log(`✅ Student ${studentId} unlinked teacher ${teacherId}`);
    
    res.json({ 
      success: true, 
      message: 'Teacher unlinked successfully. They can add you again.' 
    });
    
  } catch (error) {
    console.error('Unlink teacher error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to unlink teacher' 
    });
  }
});

// POST /api/student/teachers/:teacherId/block
app.post('/api/student/teachers/:teacherId/block', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const teacherId = req.params.teacherId;
    
    // Find the link
    const link = await TeacherStudentLink.findOne({
      teacherId: teacherId,
      studentId: studentId
    });
    
    if (!link) {
      return res.status(404).json({ 
        success: false,
        error: 'Teacher link not found' 
      });
    }
    
    // Block: Deactivate link + mark as blocked (teacher CANNOT re-add)
    link.isActive = false;
    link.isBlocked = true;
    link.blockedAt = new Date();
    link.blockedBy = 'student';
    await link.save();
    
    // Also add to user block list (for calls/messages)
    const existingBlock = await UserBlock.findOne({ 
      blockerId: studentId, 
      blockedId: teacherId 
    });
    
    if (!existingBlock) {
      await UserBlock.create({ 
        blockerId: studentId, 
        blockedId: teacherId 
      });
    }
    
    console.log(`🚫 Student ${studentId} blocked teacher ${teacherId}`);
    
    res.json({ 
      success: true, 
      message: 'Teacher blocked successfully. They cannot add you until you unblock them.' 
    });
    
  } catch (error) {
    console.error('Block teacher error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to block teacher' 
    });
  }
});

// POST /api/student/teachers/:teacherId/unblock
app.post('/api/student/teachers/:teacherId/unblock', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const teacherId = req.params.teacherId;
    
    // Find the blocked link
    const link = await TeacherStudentLink.findOne({
      teacherId: teacherId,
      studentId: studentId
    });
    
    if (!link) {
      return res.status(404).json({ 
        success: false,
        error: 'Teacher link not found' 
      });
    }
    
    // Unblock: Remove block status
    link.isBlocked = false;
    link.blockedAt = null;
    link.blockedBy = null;
    await link.save();
    
    // Remove from user block list
    await UserBlock.findOneAndDelete({ 
      blockerId: studentId, 
      blockedId: teacherId 
    });
    
    console.log(`✅ Student ${studentId} unblocked teacher ${teacherId}`);
    
    res.json({ 
      success: true, 
      message: 'Teacher unblocked successfully. They can now add you again.' 
    });
    
  } catch (error) {
    console.error('Unblock teacher error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to unblock teacher' 
    });
  }
});

app.get('/api/student/classes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, classes: [] });
    }
    
    // ========= FETCH REGULAR CLASSES =========
    const regularClasses = await ClassModel.find({
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
    
    // ========= FETCH GROUP CLASSES =========
    // Find sections this student is in
    const studentSections = await Section.find({
      teacherId: { $in: linkedTeacherIds },
      studentIds: studentId,
      isActive: true
    }).select('_id');
    
    const sectionIds = studentSections.map(s => s._id);
    
    // Get group classes where student is eligible
    const groupClasses = await GroupClass.find({
      teacherId: { $in: linkedTeacherIds },
      isActive: true,
      status: { $in: ['SCHEDULED', 'LIVE'] }, // Only show upcoming/active classes
      $or: [
        { isForAllStudents: true }, // Classes for all students
        { studentIds: studentId }, // Directly assigned to student
        { sectionId: { $in: sectionIds } } // Student's section is assigned
      ]
    })
    .populate('teacherId', 'name')
    .populate('sectionId', 'name')
    .sort({ scheduledAt: 1 })
    .lean();
    
    // ========= FORMAT REGULAR CLASSES =========
    const formattedRegularClasses = regularClasses.map(c => ({
      id: c._id.toString(),
      type: 'REGULAR', // ✅ Add type field
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
    
    // ========= FORMAT GROUP CLASSES =========
    const formattedGroupClasses = groupClasses.map(c => ({
      id: c._id.toString(),
      type: 'GROUP', // ✅ Add type field
      subject: c.subject,
      title: c.title,
      description: c.description,
      scheduledAt: c.scheduledAt.toISOString(),
      duration: c.duration,
      colorHex: c.colorHex || '#10B981',
      notes: c.notes,
      teacherName: c.teacherId?.name,
      sectionName: c.sectionId?.name,
      status: c.status,
      sessionId: c.sessionId,
      // Settings
      allowStudentVideo: c.allowStudentVideo,
      allowStudentAudio: c.allowStudentAudio,
      allowChat: c.allowChat,
      allowScreenShare: c.allowScreenShare,
      allowWhiteboard: c.allowWhiteboard,
      // Times
      startedAt: c.startedAt?.toISOString(),
      endedAt: c.endedAt?.toISOString()
    }));
    
    // ========= COMBINE BOTH =========
    const allClasses = [
      ...formattedRegularClasses,
      ...formattedGroupClasses
    ];
    
    res.json({ 
      success: true, 
      classes: allClasses,
      summary: {
        regularClasses: formattedRegularClasses.length,
        groupClasses: formattedGroupClasses.length,
        total: allClasses.length
      }
    });
    
  } catch (error) {
    console.error('Student classes error:', error);
    res.status(500).json({ error: 'Failed to fetch classes' });
  }
});

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

app.get('/api/student/results', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, results: [] });
    }
    
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

// ========= TEACHER ENDPOINTS =========
app.get('/api/teacher/dashboard', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;

    const studentCount = await TeacherStudentLink.countDocuments({ teacherId, isActive: true });
    const classCount = await ClassModel.countDocuments({ teacherId, isActive: true });
    const assignmentCount = await Assignment.countDocuments({ teacherId });
    const examCount = await Exam.countDocuments({ teacherId, isActive: true });

    const assignments = await Assignment.find({ teacherId }).select('_id');
    const assignmentIds = assignments.map(a => a._id);
    const pendingSubmissions = await AssignmentSubmission.countDocuments({
      assignmentId: { $in: assignmentIds },
      status: { $in: ['SUBMITTED', 'LATE'] }
    });

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

// ========= TEACHER ANALYTICS ENDPOINTS =========

// Analytics Overview - GET /api/teacher/analytics/overview
app.get('/api/teacher/analytics/overview', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;

    // Get student count
    const studentCount = await TeacherStudentLink.countDocuments({ 
      teacherId, 
      isActive: true 
    });

    // Get active class count
    const classCount = await ClassModel.countDocuments({ 
      teacherId, 
      isActive: true 
    });

    // Get pending assignment submissions count
    const assignments = await Assignment.find({ teacherId }).select('_id');
    const assignmentIds = assignments.map(a => a._id);
    const pendingAssignments = await AssignmentSubmission.countDocuments({
      assignmentId: { $in: assignmentIds },
      status: { $in: ['SUBMITTED', 'LATE'] }
    });

    // Get upcoming exams (next 7 days)
    const today = new Date();
    const nextWeek = new Date();
    nextWeek.setDate(today.getDate() + 7);
    
    const upcomingExams = await Exam.countDocuments({
      teacherId,
      isActive: true,
      whenAt: { $gte: today, $lte: nextWeek }
    });

    res.json({
      success: true,
      studentCount,
      classCount,
      pendingAssignments,
      upcomingExams
    });

  } catch (error) {
    console.error('Analytics overview error:', error);
    res.status(500).json({ error: 'Failed to fetch analytics overview' });
  }
});

// Student Analytics - GET /api/teacher/analytics/:studentId
app.get('/api/teacher/analytics/:studentId', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const teacherId = req.userId;
    const studentId = req.params.studentId;

    // Verify teacher owns this student
    const isLinked = await ensureTeacherOwnsStudent(teacherId, studentId);
    if (!isLinked) {
      return res.status(403).json({ error: 'Not authorized to view this student\'s analytics' });
    }

    // Get all attendance records for this student
    const attendanceRecords = await Attendance.find({
      teacherId: teacherId,
      'marks.studentId': studentId
    }).lean();

    let attended = 0;
    let missed = 0;
    let cancelled = 0;

    // Count attendance stats
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

    // Calculate attendance rate
    const totalClasses = attended + missed;
    const attendanceRate = totalClasses > 0 
      ? (attended / totalClasses) * 100 
      : 0;

    res.json({
      success: true,
      attended,
      missed,
      cancelled, // Currently 0, can be enhanced later
      attendanceRate: Math.round(attendanceRate * 100) / 100
    });

  } catch (error) {
    console.error('Student analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch student analytics' });
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
      endTime: endTime || startTime,
      colorHex: colorHex || '#3B82F6',
      notes: notes || '',
      location: location || '',
      scope: scope || 'ALL',
      studentId: scope === 'INDIVIDUAL' ? studentId : null,
      isActive: true
    };

    const newClass = await ClassModel.create(classData);

    if (scope === 'ALL') {
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
      isActive: true
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
app.get('/api/teacher/assignments', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const assignments = await Assignment.find({ teacherId: req.userId })
      .sort({ dueAt: 1 })
      .lean();

    const formattedAssignments = assignments.map(assignment => ({
      id: assignment._id.toString(),
      title: assignment.title,
      dueAt: assignment.dueAt ? assignment.dueAt.toISOString() : null,
      description: assignment.description,
      notes: assignment.notes,
      priority: assignment.priority
    }));

    res.json({ success: true, assignments: formattedAssignments });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch assignments' });
  }
});

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

    await AssignmentSubmission.deleteMany({ assignmentId });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete assignment' });
  }
});

app.get('/api/teacher/assignments/:id/submissions', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const assignmentId = req.params.id;

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

app.put('/api/teacher/submissions/:id/grade', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const submissionId = req.params.id;
    const { marks, feedback } = req.body;

    const submission = await AssignmentSubmission.findById(submissionId).populate('assignmentId');
    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

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
app.get('/api/teacher/notes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const notes = await Note.find({ teacherId: req.userId })
      .sort({ createdAt: -1 })
      .lean();

    const formattedNotes = notes.map(note => ({
      id: note._id.toString(),
      title: note.title,
      content: note.content,
      subject: note.subject
    }));

    res.json({ success: true, notes: formattedNotes });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch notes' });
  }
});

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

// ========= EXAM MANAGEMENT =========
app.get('/api/teacher/exams', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const exams = await Exam.find({ 
      teacherId: req.userId,
      isActive: true
    })
    .sort({ whenAt: 1 })
    .lean();

    const formattedExams = exams.map(exam => ({
      id: exam._id.toString(),
      title: exam.title,
      whenAt: exam.whenAt.toISOString(),
      description: exam.description,
      location: exam.location,
      maxMarks: exam.maxMarks,
      duration: exam.duration
    }));

    res.json({ success: true, exams: formattedExams });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch exams' });
  }
});

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

// ========= RESULT MANAGEMENT =========
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

// Get group classes for student
// Get group classes for student - FIXED VERSION
// Get group classes for student - FIXED VERSION
app.get('/api/group-classes', authRequired, async (req, res) => {
    try {
        const role = req.role;
        const userId = req.userId;

        let query = {
            isActive: true,
            status: { $in: ['SCHEDULED', 'LIVE'] }
        };

        if (role === 'STUDENT') {
            // Get linked teachers
            const links = await TeacherStudentLink.find({
                studentId: userId,
                isActive: true
            }).select('teacherId');
            
            const linkedTeacherIds = links.map(link => link.teacherId);

            if (linkedTeacherIds.length === 0) {
                return res.json({ success: true, classes: [] });
            }

            // Find sections this student is in
            const studentSections = await Section.find({
                teacherId: { $in: linkedTeacherIds },
                studentIds: userId,
                isActive: true
            }).select('_id');

            const sectionIds = studentSections.map(s => s._id);

            // Query for group classes
            query.teacherId = { $in: linkedTeacherIds };
            query.$or = [
                { isForAllStudents: true },
                { studentIds: userId },
                { sectionId: { $in: sectionIds } }
            ];
        } else if (role === 'TEACHER') {
            query.teacherId = userId;
        }

        const classes = await GroupClass.find(query)
            .populate('teacherId', 'name avatar')
            .populate('sectionId', 'name')
            .sort({ scheduledAt: 1 });

        // Format response
        const formatted = classes.map(cls => ({
            id: cls._id.toString(),
            title: cls.title,
            subject: cls.subject,
            description: cls.description,
            scheduledAt: cls.scheduledAt,
            duration: cls.duration,
            teacherName: cls.teacherId?.name,
            teacherAvatar: cls.teacherId?.avatar,
            sectionName: cls.sectionId?.name,
            status: cls.status,
            sessionId: cls.sessionId,
            colorHex: cls.colorHex || '#10B981',
            allowStudentVideo: cls.allowStudentVideo,
            allowStudentAudio: cls.allowStudentAudio,
            allowChat: cls.allowChat,
            allowScreenShare: cls.allowScreenShare,
            allowWhiteboard: cls.allowWhiteboard
        }));

        res.json({ success: true, classes: formatted });
    } catch (error) {
        console.error('Get group classes error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Join by student code
// Join by student code - FIXED
app.post('/api/group-classes/join-by-code', authRequired, async (req, res) => {
    try {
        const { code } = req.body;
        const userId = req.userId;
        const role = req.role;
        
        if (role !== 'STUDENT') {
            return res.status(403).json({ success: false, message: 'Students only' });
        }
        
        if (!code || code.length !== 6) {
            return res.status(400).json({ success: false, message: 'Valid 6-digit code required' });
        }
        
        // Find group class by session ID (not studentCode)
        const groupClass = await GroupClass.findOne({ 
            sessionId: { $regex: code, $options: 'i' },
            isActive: true,
            status: { $in: ['SCHEDULED', 'LIVE'] }
        }).populate('teacherId', 'name');
        
        if (!groupClass) {
            return res.status(404).json({ success: false, message: 'Invalid or expired class code' });
        }
        
        // Check if student is linked to teacher
        const isLinked = await ensureTeacherOwnsStudent(groupClass.teacherId._id, userId);
        if (!isLinked) {
            return res.status(403).json({ success: false, message: 'You must be linked to this teacher first' });
        }
        
        // Add student if not already enrolled
        if (!groupClass.studentIds.includes(userId)) {
            groupClass.studentIds.push(userId);
            await groupClass.save();
        }
        
        res.json({ 
            success: true, 
            class: {
                id: groupClass._id.toString(),
                title: groupClass.title,
                subject: groupClass.subject,
                sessionId: groupClass.sessionId,
                scheduledAt: groupClass.scheduledAt
            },
            message: 'Successfully joined class!'
        });
    } catch (error) {
        console.error('Join by code error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ========= ATTENDANCE MANAGEMENT =========
app.post('/api/teacher/attendance', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { classId, date, marks } = req.body;

    if (!classId || !date || !Array.isArray(marks)) {
      return res.status(400).json({ error: 'Class ID, date, and marks array are required' });
    }

    const classExists = await ClassModel.findOne({ _id: classId, teacherId: req.userId });
    if (!classExists) {
      return res.status(404).json({ error: 'Class not found' });
    }

    for (const mark of marks) {
      if (!mark || !mark.studentId) continue;
      const isLinked = await ensureTeacherOwnsStudent(req.userId, mark.studentId);
      if (!isLinked) {
        return res.status(403).json({ error: `Not linked to student ${mark.studentId}` });
      }
    }

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
app.get('/api/planner/tasks', authRequired, async (req, res) => {
  try {
    const { startDate, endDate, type, completed } = req.query;
    
    let query = { userId: req.userId };
    
    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }
    
    if (type && type !== 'ALL') {
      query.type = type;
    }
    
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

app.put('/api/planner/tasks/:id', authRequired, async (req, res) => {
  try {
    const taskId = req.params.id;
    const updates = req.body;
    
    const task = await PlannerTask.findOne({ _id: taskId, userId: req.userId });
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
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

app.get('/api/planner/stats', authRequired, async (req, res) => {
  try {
    const userId = req.userId;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    const todayTasks = await PlannerTask.countDocuments({
      userId,
      date: { $gte: today, $lt: tomorrow }
    });
    
    const todayCompleted = await PlannerTask.countDocuments({
      userId,
      date: { $gte: today, $lt: tomorrow },
      completed: true
    });
    
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

// ========= CHAT ENDPOINTS =========
app.get('/api/chat/conversations', authRequired, async (req, res) => {
  try {
    const userId = req.userId;
    const role = req.role;
    
    // Get linked users instead of stored conversations
    let linkedUsers = [];
    
    if (role === 'TEACHER') {
      const links = await TeacherStudentLink.find({ 
        teacherId: userId, 
        isActive: true,
        isBlocked: { $ne: true }
      }).populate('studentId', 'name email avatar studentCode isOnline lastSeen');
      
      linkedUsers = links.map(link => ({
        id: `conv_${userId}_${link.studentId._id}`,
        otherUser: {
          id: link.studentId._id.toString(),
          name: link.studentId.name,
          avatar: link.studentId.avatar,
          role: 'STUDENT',
          email: link.studentId.email,
          studentCode: link.studentId.studentCode,
          isOnline: link.studentId.isOnline,
          lastSeen: link.studentId.lastSeen
        },
        teacher: { id: userId, name: 'Me', role: 'TEACHER' },
        student: {
          id: link.studentId._id.toString(),
          name: link.studentId.name,
          role: 'STUDENT'
        },
        lastMessage: null,
        lastMessageAt: null,
        unreadCount: 0,
        createdAt: link.linkedAt
      }));
    } else {
      const links = await TeacherStudentLink.find({ 
        studentId: userId, 
        isActive: true,
        isBlocked: { $ne: true }
      }).populate('teacherId', 'name email avatar isOnline lastSeen');
      
      linkedUsers = links.map(link => ({
        id: `conv_${link.teacherId._id}_${userId}`,
        otherUser: {
          id: link.teacherId._id.toString(),
          name: link.teacherId.name,
          avatar: link.teacherId.avatar,
          role: 'TEACHER',
          email: link.teacherId.email,
          isOnline: link.teacherId.isOnline,
          lastSeen: link.teacherId.lastSeen
        },
        teacher: {
          id: link.teacherId._id.toString(),
          name: link.teacherId.name,
          role: 'TEACHER'
        },
        student: { id: userId, name: 'Me', role: 'STUDENT' },
        lastMessage: null,
        lastMessageAt: null,
        unreadCount: 0,
        createdAt: link.linkedAt
      }));
    }
    
    res.json({ success: true, conversations: linkedUsers });
  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).json({ error: 'Failed to fetch conversations' });
  }
});

app.get('/api/chat/conversations/:id/messages', authRequired, async (req, res) => {
  // Messages are stored locally on devices now
  // This endpoint returns empty - app uses local Room database
  res.json({ success: true, messages: [] });
});

app.post('/api/chat/upload-file', authRequired, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
    res.json({
      success: true,
      fileUrl,
      fileName: req.file.originalname,
      fileSize: req.file.size,
      mimeType: req.file.mimetype
    });
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

// ========= VOICE MESSAGE UPLOAD =========
// Make sure multer is configured for 'voice' field
app.post('/api/chat/upload-voice', authRequired, upload.single('voice'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No voice file uploaded' });
    }
    
    const allowedAudioTypes = ['audio/mpeg', 'audio/mp3', 'audio/mp4', 'audio/3gpp', 'audio/aac', 'audio/wav', 'audio/ogg'];
    if (!allowedAudioTypes.includes(req.file.mimetype)) {
      return res.status(400).json({ error: 'Only audio files are allowed' });
    }
    
    const duration = parseInt(req.body.duration) || 0;
    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
    res.json({
      success: true,
      fileUrl,
      fileName: req.file.originalname,
      fileSize: req.file.size,
      mimeType: req.file.mimetype,
      duration: duration
    });
  } catch (error) {
    console.error('Voice upload error:', error);
    res.status(500).json({ error: 'Failed to upload voice message' });
  }
});

// 🚀 UPDATED: Local-first message deletion (relay-only approach)
// 🚀 FIXED: Local-first message deletion (supports both query params and body)
app.delete('/api/chat/messages/:id', authRequired, async (req, res) => {
  try {
    const messageId = req.params.id;
    const deleteForEveryone = req.query.deleteForEveryone === 'true';
    
    // 🚀 FIX: Get conversationId from query params OR body (flexible)
    const conversationId = req.query.conversationId || req.body.conversationId;
    const userId = req.userId;
    
    if (!conversationId) {
      return res.status(400).json({ 
        error: 'conversationId is required (as query parameter or in body)',
        example: '/api/chat/messages/:id?conversationId=conv_123&deleteForEveryone=true'
      });
    }
    
    // Get user info for relay
    const user = await User.findById(userId).select('name');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // 🚀 LOCAL-FIRST: Just relay deletion event, no MongoDB operations
    const deletionData = {
      messageId,
      conversationId,
      deletedBy: userId,
      deletedByName: user.name,
      deleteForEveryone: deleteForEveryone,
      deletedAt: new Date().toISOString()
    };
    
    // Emit deletion to conversation participants
    io.to(`conversation_${conversationId}`).emit('message_deleted', deletionData);
    
    console.log(`🗑️ Message deletion relayed: ${messageId} (deleteForEveryone: ${deleteForEveryone})`);
    
    res.json({ 
      success: true, 
      message: deleteForEveryone ? 'Message deleted for everyone' : 'Message deleted for you',
      deletionData 
    });
    
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// 🚀 NEW: Batch message deletion for "Clear Chat" functionality
app.post('/api/chat/conversations/:id/clear', authRequired, async (req, res) => {
  try {
    const conversationId = req.params.id;
    const { deleteForEveryone = false } = req.body;
    const userId = req.userId;
    
    const user = await User.findById(userId).select('name');
    
    const clearData = {
      conversationId,
      clearedBy: userId,
      clearedByName: user.name,
      deleteForEveryone: deleteForEveryone,
      clearedAt: new Date().toISOString()
    };
    
    // Relay clear event to all participants
    io.to(`conversation_${conversationId}`).emit('conversation_cleared', clearData);
    
    res.json({ 
      success: true, 
      message: deleteForEveryone ? 'Chat cleared for everyone' : 'Chat cleared for you' 
    });
    
  } catch (error) {
    console.error('Clear conversation error:', error);
    res.status(500).json({ error: 'Failed to clear conversation' });
  }
});



app.post('/api/chat/messages/:id/copy', authRequired, async (req, res) => {
  try {
    const messageId = req.params.id;
    const userId = req.userId;
    
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    const conversation = await Conversation.findById(message.conversationId);
    if (conversation.teacherId.toString() !== userId && conversation.studentId.toString() !== userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    res.json({ 
      success: true, 
      content: message.content,
      type: message.type
    });
  } catch (error) {
    console.error('Copy message error:', error);
    res.status(500).json({ error: 'Failed to copy message' });
  }
});



// Delete conversation - FIXED VERSION
app.delete('/api/chat/conversations/:id', authRequired, async (req, res) => {
  try {
    const conversationId = req.params.id;
    const userId = req.userId;
    const role = req.role;
    
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    
    if (conversation.teacherId.toString() !== userId && 
        conversation.studentId.toString() !== userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    // Mark messages as deleted for this user
    await Message.updateMany(
      { conversationId: conversationId },
      { $addToSet: { deletedForUsers: userId } }
    );
    
    // ✅ FIX: ACTUALLY DELETE the conversation document
    // This removes it from the chat list
    await Conversation.findByIdAndDelete(conversationId);
    
    // IMPORTANT: Teacher-student link is NOT affected
    // User can re-add via + button because link still exists
    
    console.log(`✅ Conversation ${conversationId} deleted successfully`);
    res.json({ success: true, message: 'Chat deleted successfully' });
    
  } catch (error) {
    console.error('Delete conversation error:', error);
    res.status(500).json({ error: 'Failed to delete conversation' });
  }
});

// ========= USER BLOCKING SYSTEM =========
app.post('/api/users/block', authRequired, async (req, res) => {
  try {
    const { userId } = req.body;
    const blockerId = req.userId;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }
    
    if (userId === blockerId) {
      return res.status(400).json({ error: 'Cannot block yourself' });
    }
    
    const existingBlock = await UserBlock.findOne({ blockerId, blockedId: userId });
    if (existingBlock) {
      return res.status(400).json({ error: 'User already blocked' });
    }
    
    await UserBlock.create({ blockerId, blockedId: userId });
    
    res.json({ success: true, message: 'User blocked successfully' });
  } catch (error) {
    console.error('Block user error:', error);
    res.status(500).json({ error: 'Failed to block user' });
  }
});

app.delete('/api/users/block/:userId', authRequired, async (req, res) => {
  try {
    const blockedId = req.params.userId;
    const blockerId = req.userId;
    
    await UserBlock.findOneAndDelete({ blockerId, blockedId });
    
    res.json({ success: true, message: 'User unblocked successfully' });
  } catch (error) {
    console.error('Unblock user error:', error);
    res.status(500).json({ error: 'Failed to unblock user' });
  }
});

app.get('/api/users/blocked', authRequired, async (req, res) => {
  try {
    const blocks = await UserBlock.find({ blockerId: req.userId })
      .populate('blockedId', 'name avatar email role')
      .lean();
    
    const blockedUsers = blocks.map(block => ({
      id: block.blockedId._id.toString(),
      name: block.blockedId.name,
      avatar: block.blockedId.avatar,
      email: block.blockedId.email,
      role: block.blockedId.role,
      blockedAt: block.createdAt
    }));
    
    res.json({ success: true, blockedUsers });
  } catch (error) {
    console.error('Get blocked users error:', error);
    res.status(500).json({ error: 'Failed to fetch blocked users' });
  }
});

// ========= PROFILE PICTURE UPLOAD =========
app.post('/api/users/avatar', authRequired, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file uploaded' });
    }
    
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(req.file.mimetype)) {
      return res.status(400).json({ error: 'Only image files are allowed' });
    }
    
    const avatarUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
    await User.findByIdAndUpdate(req.userId, { avatar: avatarUrl });
    
    res.json({
      success: true,
      avatarUrl: avatarUrl
    });
  } catch (error) {
    console.error('Avatar upload error:', error);
    res.status(500).json({ error: 'Failed to upload avatar' });
  }
});

// ========= GET USER PROFILE BY ID =========
// Add this after the /api/users/avatar endpoint
app.get('/api/users/:userId', authRequired, async (req, res) => {
  try {
    const requestedUserId = req.params.userId;
    const currentUserId = req.userId;
    const currentUserRole = req.role;
    
    // Find the requested user
    const user = await User.findById(requestedUserId)
      .select('name email avatar role studentCode isOnline lastSeen')
      .lean();
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }
    
    // Authorization check: Only allow viewing profiles of linked users
    if (currentUserRole === 'TEACHER') {
      // Teacher can view their students
      const link = await TeacherStudentLink.findOne({
        teacherId: currentUserId,
        studentId: requestedUserId,
        isActive: true
      });
      
      if (!link && requestedUserId !== currentUserId) {
        return res.status(403).json({ 
          success: false,
          error: 'Not authorized to view this profile' 
        });
      }
    } else if (currentUserRole === 'STUDENT') {
      // Student can view their teachers
      const link = await TeacherStudentLink.findOne({
        teacherId: requestedUserId,
        studentId: currentUserId,
        isActive: true
      });
      
      if (!link && requestedUserId !== currentUserId) {
        return res.status(403).json({ 
          success: false,
          error: 'Not authorized to view this profile' 
        });
      }
    }
    
    // Return user profile
    res.json({
      success: true,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        role: user.role,
        studentCode: user.studentCode,
        isOnline: user.isOnline,
        lastSeen: user.lastSeen
      }
    });
    
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch user profile' 
    });
  }
});

// Add this to your backend with your other chat endpoints
app.post('/api/chat/messages/new', authRequired, async (req, res) => {
  try {
    const { receiverId, content, type = 'TEXT', replyTo } = req.body;
    const senderId = req.userId;
    const senderRole = req.role;
    
    if (!receiverId || !content) {
      return res.status(400).json({ 
        success: false, 
        error: 'receiverId and content are required' 
      });
    }
    
    // Determine conversation participants based on roles
    let teacherId, studentId;
    if (senderRole === 'TEACHER') {
      teacherId = senderId;
      studentId = receiverId;
    } else {
      studentId = senderId;
      teacherId = receiverId;
    }
    
    // Check if conversation already exists
    let conversation = await Conversation.findOne({
      teacherId: teacherId,
      studentId: studentId
    });
    
    // Create conversation if it doesn't exist
    if (!conversation) {
      conversation = new Conversation({
        teacherId: teacherId,
        studentId: studentId,
        createdAt: new Date()
      });
      await conversation.save();
      console.log(`Created new conversation: ${conversation._id}`);
    }
    
    // Build message data
    const messageData = {
      conversationId: conversation._id,
      senderId: senderId,
      receiverId: receiverId,
      content: content,
      type: type,
      createdAt: new Date(),
      delivered: false,
      read: false
    };
    
    // Add replyTo if provided
    if (replyTo && replyTo.messageId) {
      messageData.replyTo = {
        messageId: replyTo.messageId,
        content: replyTo.content || '',
        senderId: replyTo.senderId,
        senderName: replyTo.senderName || 'Unknown',
        type: replyTo.type || 'TEXT'
      };
    }
    
    // Create and save the message
    const message = new Message(messageData);
    
    await message.save();
    
    // Update conversation with last message info
    conversation.lastMessage = content;
    conversation.lastMessageAt = new Date();
    conversation.lastMessageSenderId = senderId;
    
    // Update unread counts
    if (senderRole === 'TEACHER') {
      conversation.unreadCountStudent += 1;
    } else {
      conversation.unreadCountTeacher += 1;
    }
    
    await conversation.save();
    
    // Emit via Socket.IO to receiver (if connected)
    io.to(`conversation_${conversation._id}`).emit('new_message', {
      id: message._id.toString(),
      conversationId: conversation._id.toString(),
      content: message.content,
      type: message.type,
      sender: {
        id: senderId,
        name: req.user?.name || 'User',
        role: senderRole
      },
      createdAt: message.createdAt,
      delivered: false,
      read: false
    });
    
    // Return success response
    res.json({
      success: true,
      conversationId: conversation._id.toString(),
      messageId: message._id.toString(),
      message: 'Message sent successfully'
    });
    
  } catch (error) {
    console.error('Send new message error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to send message' 
    });
  }
});

// ========= WEBRTC TURN CREDENTIALS API =========
// ========= WEBRTC TURN CREDENTIALS API =========
app.get('/api/webrtc/turn-credentials', authRequired, async (req, res) => {
  try {
    const iceServers = [
      // Google STUN servers (public, no auth needed)
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      { urls: 'stun:stun2.l.google.com:19302' },
      { urls: 'stun:stun3.l.google.com:19302' },
      { urls: 'stun:stun4.l.google.com:19302' },
      
      // Additional STUN servers
      { urls: 'stun:stun.stunprotocol.org:3478' },
      { urls: 'stun:stun.voipbuster.com:3478' },
      { urls: 'stun:stun.voipstunt.com:3478' },
      
      // ExpressTurn TURN Server (Primary)
      {
        urls: [
          `turn:${process.env.EXPRESSTURN_URL || 'relay1.expressturn.com:3480'}`,
          `turns:${process.env.EXPRESSTURN_URL || 'relay1.expressturn.com:3480'}`
        ],
        username: process.env.EXPRESSTURN_USERNAME || '000000002079286307',
        credential: process.env.EXPRESSTURN_PASSWORD || '1/1pyKIyWpQE+jpjV7VzYgx3tQE='
      },
      
      // Xirsys TURN (Fallback #1)
      {
        urls: [
          `turn:${process.env.XIRSYS_URL || 'bn-turn1.xirsys.com'}:80?transport=udp`,
          `turn:${process.env.XIRSYS_URL || 'bn-turn1.xirsys.com'}:3478?transport=udp`
        ],
        username: process.env.XIRSYS_USERNAME || 'YzYNCouZM1mhqhmseWk6',
        credential: process.env.XIRSYS_PASSWORD || 'YzYNCouZM1mhqhmseWk6'
      },
      
      // Metered.ca TURN (Fallback #2 - Public)
      {
        urls: [
          `turn:${process.env.METERED_URL || 'openrelay.metered.ca'}:80`,
          `turn:${process.env.METERED_URL || 'openrelay.metered.ca'}:443`
        ],
        username: process.env.METERED_USERNAME || 'openrelayproject',
        credential: process.env.METERED_PASSWORD || 'openrelayproject'
      }
    ];
    
    console.log(`🔐 TURN credentials requested by user ${req.userId}`);
    
    res.json({
      iceServers: iceServers.map(server => ({
        urls: Array.isArray(server.urls) ? server.urls : [server.urls],
        username: server.username || undefined,
        credential: server.credential || undefined
      }))
    });
    
  } catch (error) {
    console.error('TURN credentials error:', error);
    res.status(500).json({ error: 'Failed to fetch TURN credentials' });
  }
});

// ========= GAMES API ENDPOINTS =========

// Get game config (subscription check)
app.get('/api/games/config', authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Teachers can't play
    if (user.role === 'TEACHER') {
      return res.json({
        success: true,
        config: {
          canPlay: false,
          isTeacher: true,
          message: 'Teachers can only view leaderboards'
        }
      });
    }
    
    // Check subscription
    const hasSubscription = user.subscriptionStatus === 'active' || user.subscriptionStatus === 'trial';
    const isExpired = user.subscriptionExpiry && new Date() > new Date(user.subscriptionExpiry);
    
    // Free: 5 games/day, Premium: unlimited
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const todayGamesCount = await GameScore.countDocuments({
      userId: req.userId,
      playedAt: { $gte: today }
    });
    
    const gamesRemaining = (hasSubscription && !isExpired) ? -1 : Math.max(0, 5 - todayGamesCount);
    
    // Get XP
    let userXP = await UserXP.findOne({ userId: req.userId });
    if (!userXP) {
      userXP = await UserXP.create({ userId: req.userId });
    }
    
    res.json({
      success: true,
      config: {
        hasSubscription: hasSubscription && !isExpired,
        gamesRemaining,
        canPlay: (hasSubscription && !isExpired) || gamesRemaining > 0,
        availableGames: ['quiz', 'math', 'memory', 'hangman'],
        totalXP: userXP.totalXP,
        level: userXP.level,
        gamesPlayed: userXP.gamesPlayed
      }
    });
  } catch (err) {
    console.error('Get config error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Submit score
app.post('/api/games/score', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const { gameType, score, xpEarned, difficulty, questionsAnswered, correctAnswers, timeTaken } = req.body;
    
    const validGames = ['quiz', 'math', 'memory', 'hangman'];
    if (!validGames.includes(gameType)) {
      return res.status(400).json({ success: false, message: 'Invalid game type' });
    }
    
    const user = await User.findById(req.userId).select('name');
    
    const gameScore = new GameScore({
      userId: req.userId,
      username: user.name,
      gameType,
      score,
      xpEarned,
      difficulty: difficulty || 'medium',
      questionsAnswered: questionsAnswered || 0,
      correctAnswers: correctAnswers || 0,
      timeTaken: timeTaken || 0,
      playedAt: new Date()
    });
    
    await gameScore.save();
    
    // Update XP
    let userXP = await UserXP.findOne({ userId: req.userId });
    if (!userXP) {
      userXP = new UserXP({ userId: req.userId });
    }
    
    userXP.totalXP += xpEarned;
    userXP.gamesPlayed += 1;
    userXP[`${gameType}XP`] = (userXP[`${gameType}XP`] || 0) + xpEarned;
    userXP.level = Math.floor(Math.sqrt(userXP.totalXP / 100)) + 1;
    userXP.lastUpdated = new Date();
    
    await userXP.save();
    
    res.json({
      success: true,
      message: 'Score saved',
      scoreId: gameScore._id,
      totalXP: userXP.totalXP,
      level: userXP.level
    });
  } catch (err) {
    console.error('Submit score error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Class leaderboard
app.get('/api/games/leaderboard/class/:teacherId', authRequired, async (req, res) => {
  try {
    const { teacherId } = req.params;
    const { gameType } = req.query;
    
    // Verify access
    if (req.role === 'STUDENT') {
      const link = await TeacherStudentLink.findOne({
        teacherId: teacherId,
        studentId: req.userId,
        isActive: true
      });
      
      if (!link) {
        return res.status(403).json({ success: false, message: 'Not linked to this teacher' });
      }
    } else if (req.role === 'TEACHER') {
      if (teacherId !== req.userId) {
        return res.status(403).json({ success: false, message: 'Not authorized' });
      }
    }
    
    // Get students
    const links = await TeacherStudentLink.find({
      teacherId: teacherId,
      isActive: true
    }).select('studentId');
    
    const studentIds = links.map(l => l.studentId);
    
    if (studentIds.length === 0) {
      return res.json({ success: true, leaderboard: [] });
    }
    
    // Build query
    let scoreQuery = { userId: { $in: studentIds } };
    if (gameType && gameType !== 'all') {
      scoreQuery.gameType = gameType;
    }
    
    // Get scores
    const scores = await GameScore.find(scoreQuery)
  .populate('userId', 'name')  // Only name for privacy
  .sort({ score: -1, playedAt: -1 })
  .lean();
    
    // Group by user
    const userScores = {};
    scores.forEach(score => {
      const userId = score.userId._id.toString();
      if (!userScores[userId]) {
        userScores[userId] = {
          userId: userId,
          username: score.userId.name,
          totalScore: 0,
          totalXP: 0,
          gamesPlayed: 0,
          lastPlayed: score.playedAt
        };
      }
      userScores[userId].totalScore += score.score;
      userScores[userId].totalXP += score.xpEarned;
      userScores[userId].gamesPlayed += 1;
      if (score.playedAt > userScores[userId].lastPlayed) {
        userScores[userId].lastPlayed = score.playedAt;
      }
    });
    
    // Sort and rank
    let leaderboard = Object.values(userScores).sort((a, b) => b.totalXP - a.totalXP);
    leaderboard = leaderboard.map((entry, index) => ({ ...entry, rank: index + 1 }));
    
    res.json({ success: true, leaderboard });
  } catch (err) {
    console.error('Class leaderboard error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// World leaderboard
app.get('/api/games/leaderboard/world', authRequired, async (req, res) => {
  try {
    const { gameType, limit = 100 } = req.query;
    
    let query = {};
    if (gameType && gameType !== 'all') {
      query.gameType = gameType;
    }
    
    const pipeline = [
      { $match: query },
      {
        $group: {
          _id: '$userId',
          username: { $first: '$username' },
          totalScore: { $sum: '$score' },
          totalXP: { $sum: '$xpEarned' },
          gamesPlayed: { $sum: 1 },
          lastPlayed: { $max: '$playedAt' }
        }
      },
      { $sort: { totalXP: -1 } },
      { $limit: parseInt(limit) }
    ];
    
    const results = await GameScore.aggregate(pipeline);
    
    const userIds = results.map(r => r._id);
    const users = await User.find({ _id: { $in: userIds } }).select('name studentCode role').lean();
    
    const userMap = {};
    users.forEach(u => { userMap[u._id.toString()] = u; });
    
    const leaderboard = results.map((result, index) => {
      const user = userMap[result._id.toString()];
      return {
        rank: index + 1,
        userId: result._id.toString(),
        username: result.username,
        totalScore: result.totalScore,
        totalXP: result.totalXP,
        gamesPlayed: result.gamesPlayed,
        lastPlayed: result.lastPlayed
      };
    });
    
    res.json({ success: true, leaderboard });
  } catch (err) {
    console.error('World leaderboard error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get student's teachers (for leaderboard selection)
app.get('/api/games/my-teachers', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const links = await TeacherStudentLink.find({
      studentId: req.userId,
      isActive: true
    })
    .populate('teacherId', 'name email avatar')
    .lean();
    
    const teachers = links.map(link => ({
      id: link.teacherId._id.toString(),
      name: link.teacherId.name,
      email: link.teacherId.email,
      avatar: link.teacherId.avatar
    }));
    
    res.json({ success: true, teachers });
  } catch (err) {
    console.error('My teachers error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Game history
app.get('/api/games/history', authRequired, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const scores = await GameScore.find({ userId: req.userId })
      .sort({ playedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();
    
    const total = await GameScore.countDocuments({ userId: req.userId });
    
    res.json({
      success: true,
      history: scores.map(s => ({
        id: s._id.toString(),
        gameType: s.gameType,
        score: s.score,
        xpEarned: s.xpEarned,
        difficulty: s.difficulty,
        questionsAnswered: s.questionsAnswered,
        correctAnswers: s.correctAnswers,
        timeTaken: s.timeTaken,
        playedAt: s.playedAt
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Game history error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ========= SECTION MANAGEMENT ENDPOINTS =========

// Get all sections
app.get('/api/teacher/sections', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const sections = await Section.find({ 
      teacherId: req.userId,
      isActive: true 
    })
    .populate('studentIds', 'name email studentCode avatar')
    .sort({ name: 1 })
    .lean();
    
    const formatted = sections.map(section => ({
      id: section._id.toString(),
      name: section.name,
      description: section.description,
      colorHex: section.colorHex,
      studentCount: section.studentIds.length,
      students: section.studentIds.map(s => ({
        id: s._id.toString(),
        name: s.name,
        email: s.email,
        studentCode: s.studentCode,
        avatar: s.avatar
      })),
      createdAt: section.createdAt
    }));
    
    res.json({ success: true, sections: formatted });
  } catch (error) {
    console.error('Get sections error:', error);
    res.status(500).json({ error: 'Failed to fetch sections' });
  }
});

// Create section
app.post('/api/teacher/sections', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { name, description, colorHex, studentIds } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Section name is required' });
    }
    
    if (studentIds && studentIds.length > 0) {
      for (const studentId of studentIds) {
        const isLinked = await ensureTeacherOwnsStudent(req.userId, studentId);
        if (!isLinked) {
          return res.status(403).json({ error: `Not authorized for student ${studentId}` });
        }
      }
    }
    
    const section = await Section.create({
      teacherId: req.userId,
      name,
      description: description || '',
      colorHex: colorHex || '#3B82F6',
      studentIds: studentIds || []
    });
    
    res.status(201).json({ success: true, sectionId: section._id.toString() });
  } catch (error) {
    console.error('Create section error:', error);
    res.status(500).json({ error: 'Failed to create section' });
  }
});

// Update section
app.put('/api/teacher/sections/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { name, description, colorHex, studentIds } = req.body;
    
    const section = await Section.findOne({ _id: req.params.id, teacherId: req.userId });
    if (!section) {
      return res.status(404).json({ error: 'Section not found' });
    }
    
    if (studentIds) {
      for (const studentId of studentIds) {
        const isLinked = await ensureTeacherOwnsStudent(req.userId, studentId);
        if (!isLinked) {
          return res.status(403).json({ error: `Not authorized for student ${studentId}` });
        }
      }
      section.studentIds = studentIds;
    }
    
    if (name) section.name = name;
    if (description !== undefined) section.description = description;
    if (colorHex) section.colorHex = colorHex;
    section.updatedAt = new Date();
    
    await section.save();
    res.status(204).send();
  } catch (error) {
    console.error('Update section error:', error);
    res.status(500).json({ error: 'Failed to update section' });
  }
});

// Delete section
app.delete('/api/teacher/sections/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const section = await Section.findOneAndUpdate(
      { _id: req.params.id, teacherId: req.userId },
      { isActive: false },
      { new: true }
    );
    
    if (!section) {
      return res.status(404).json({ error: 'Section not found' });
    }
    
    res.status(204).send();
  } catch (error) {
    console.error('Delete section error:', error);
    res.status(500).json({ error: 'Failed to delete section' });
  }
});

// ========= GROUP CLASS ENDPOINTS =========

// Get all group classes for teacher
app.get('/api/teacher/group-classes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const classes = await GroupClass.find({ 
      teacherId: req.userId,
      isActive: true 
    })
    .populate('sectionId', 'name')
    .populate('studentIds', 'name studentCode')
    .sort({ scheduledAt: -1 })
    .lean();
    
    const formatted = classes.map(cls => ({
      id: cls._id.toString(),
      title: cls.title,
      subject: cls.subject,
      description: cls.description,
      scheduledAt: cls.scheduledAt,
      duration: cls.duration,
      sectionName: cls.sectionId?.name,
      studentCount: cls.isForAllStudents ? 'All Students' : cls.studentIds.length,
      status: cls.status,
      sessionId: cls.sessionId,
      settings: {
        allowStudentVideo: cls.allowStudentVideo,
        allowStudentAudio: cls.allowStudentAudio,
        allowChat: cls.allowChat,
        allowScreenShare: cls.allowScreenShare,
        allowWhiteboard: cls.allowWhiteboard
      },
      createdAt: cls.createdAt
    }));
    
    res.json({ success: true, classes: formatted });
  } catch (error) {
    console.error('Get group classes error:', error);
    res.status(500).json({ error: 'Failed to fetch group classes' });
  }
});

// Get upcoming group classes for student
app.get('/api/student/group-classes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    const linkedTeacherIds = await getLinkedTeacherIds(studentId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ success: true, classes: [] });
    }
    
    const now = new Date();
    const classes = await GroupClass.find({
      teacherId: { $in: linkedTeacherIds },
      isActive: true,
      scheduledAt: { $gte: now },
      $or: [
        { isForAllStudents: true },
        { studentIds: studentId }
      ]
    })
    .populate('teacherId', 'name avatar')
    .sort({ scheduledAt: 1 })
    .lean();
    
    const formatted = classes.map(cls => ({
      id: cls._id.toString(),
      title: cls.title,
      subject: cls.subject,
      description: cls.description,
      scheduledAt: cls.scheduledAt,
      duration: cls.duration,
      teacherName: cls.teacherId.name,
      teacherAvatar: cls.teacherId.avatar,
      status: cls.status,
      sessionId: cls.sessionId,
      canJoin: cls.status === 'LIVE',
      colorHex: cls.colorHex
    }));
    
    res.json({ success: true, classes: formatted });
  } catch (error) {
    console.error('Get student group classes error:', error);
    res.status(500).json({ error: 'Failed to fetch group classes' });
  }
});

// Create group class
app.post('/api/teacher/group-classes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const {
      title, subject, description, scheduledAt, duration,
      sectionId, studentIds, isForAllStudents,
      allowStudentVideo, allowStudentAudio, allowChat,
      allowScreenShare, allowWhiteboard, recordSession,
      colorHex, notes
    } = req.body;
    
    if (!title || !subject || !scheduledAt) {
      return res.status(400).json({ error: 'Title, subject, and scheduled time are required' });
    }
    
    // Verify students
    if (!isForAllStudents) {
      const studentsToVerify = studentIds || [];
      for (const studentId of studentsToVerify) {
        const isLinked = await ensureTeacherOwnsStudent(req.userId, studentId);
        if (!isLinked) {
          return res.status(403).json({ error: `Not authorized for student ${studentId}` });
        }
      }
    }
    
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const groupClass = await GroupClass.create({
      teacherId: req.userId,
      title,
      subject,
      description: description || '',
      scheduledAt: new Date(scheduledAt),
      duration: duration || 60,
      sectionId: sectionId || null,
      studentIds: isForAllStudents ? [] : (studentIds || []),
      isForAllStudents: isForAllStudents || false,
      allowStudentVideo: allowStudentVideo !== false,
      allowStudentAudio: allowStudentAudio !== false,
      allowChat: allowChat !== false,
      allowScreenShare: allowScreenShare || false,
      allowWhiteboard: allowWhiteboard !== false,
      recordSession: recordSession || false,
      sessionId,
      colorHex: colorHex || '#10B981',
      notes: notes || ''
    });
    
    // Notify students
    let studentsToNotify = [];
    if (isForAllStudents) {
      const links = await TeacherStudentLink.find({ teacherId: req.userId, isActive: true });
      studentsToNotify = links.map(l => l.studentId);
    } else if (sectionId) {
      const section = await Section.findById(sectionId);
      if (section) studentsToNotify = section.studentIds;
    } else {
      studentsToNotify = studentIds || [];
    }
    
    for (const studentId of studentsToNotify) {
      await createNotification(
        studentId,
        'CLASS',
        'New Online Class Scheduled',
        `${title} scheduled for ${new Date(scheduledAt).toLocaleString()}`,
        { groupClassId: groupClass._id, sessionId }
      );
    }
    
    res.status(201).json({ 
      success: true, 
      classId: groupClass._id.toString(),
      sessionId 
    });
  } catch (error) {
    console.error('Create group class error:', error);
    res.status(500).json({ error: 'Failed to create group class' });
  }
});

// Update group class
app.put('/api/teacher/group-classes/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const groupClass = await GroupClass.findOne({ _id: req.params.id, teacherId: req.userId });
    if (!groupClass) {
      return res.status(404).json({ error: 'Group class not found' });
    }
    
    const {
      title, subject, description, scheduledAt, duration,
      allowStudentVideo, allowStudentAudio, allowChat,
      allowScreenShare, allowWhiteboard
    } = req.body;
    
    if (title) groupClass.title = title;
    if (subject) groupClass.subject = subject;
    if (description !== undefined) groupClass.description = description;
    if (scheduledAt) groupClass.scheduledAt = new Date(scheduledAt);
    if (duration) groupClass.duration = duration;
    if (allowStudentVideo !== undefined) groupClass.allowStudentVideo = allowStudentVideo;
    if (allowStudentAudio !== undefined) groupClass.allowStudentAudio = allowStudentAudio;
    if (allowChat !== undefined) groupClass.allowChat = allowChat;
    if (allowScreenShare !== undefined) groupClass.allowScreenShare = allowScreenShare;
    if (allowWhiteboard !== undefined) groupClass.allowWhiteboard = allowWhiteboard;
    
    groupClass.updatedAt = new Date();
    await groupClass.save();
    
    res.status(204).send();
  } catch (error) {
    console.error('Update group class error:', error);
    res.status(500).json({ error: 'Failed to update group class' });
  }
});

// Start group class (teacher)
// Start group class (teacher) - FIXED VERSION
app.post('/api/teacher/group-classes/:id/start', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const groupClass = await GroupClass.findOne({ _id: req.params.id, teacherId: req.userId });
    if (!groupClass) {
      return res.status(404).json({ error: 'Group class not found' });
    }
    
    // Update class status
    groupClass.status = 'LIVE';
    groupClass.startedAt = new Date();
    await groupClass.save();
    
    // ✅ FIX: Use findOneAndUpdate with upsert to handle rejoining
    await GroupCallParticipant.findOneAndUpdate(
      { 
        sessionId: groupClass.sessionId, 
        userId: req.userId 
      },
      {
        role: 'HOST',
        socketId: connectedUsers.get(req.userId),
        connectionState: 'CONNECTED',
        isVideoEnabled: true,
        isAudioEnabled: true,
        joinedAt: new Date(),
        leftAt: null  // Clear leftAt in case of rejoin
      },
      { 
        upsert: true,  // Create if doesn't exist, update if it does
        new: true 
      }
    );
    
    // Notify all students
    let studentIds = [];
    if (groupClass.isForAllStudents) {
      const links = await TeacherStudentLink.find({ teacherId: req.userId, isActive: true });
      studentIds = links.map(l => l.studentId.toString());
    } else {
      studentIds = groupClass.studentIds.map(id => id.toString());
    }
    
    for (const studentId of studentIds) {
      io.to(studentId).emit('class_started', {
        classId: groupClass._id.toString(),
        sessionId: groupClass.sessionId,
        title: groupClass.title,
        teacherId: req.userId
      });
      
      await createNotification(
        studentId,
        'CLASS',
        'Class Started',
        `${groupClass.title} is now live!`,
        { groupClassId: groupClass._id, sessionId: groupClass.sessionId }
      );
    }
    
    console.log(`✅ Class ${groupClass._id} started by teacher ${req.userId}`);
    
    res.json({ 
      success: true, 
      sessionId: groupClass.sessionId,
      message: 'Class started successfully' 
    });
  } catch (error) {
    console.error('Start group class error:', error);
    res.status(500).json({ error: 'Failed to start class' });
  }
});

// End group class
app.post('/api/teacher/group-classes/:id/end', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const groupClass = await GroupClass.findOne({ _id: req.params.id, teacherId: req.userId });
    if (!groupClass) {
      return res.status(404).json({ error: 'Group class not found' });
    }
    
    groupClass.status = 'ENDED';
    groupClass.endedAt = new Date();
    await groupClass.save();
    
    // Update all participants
    await GroupCallParticipant.updateMany(
      { sessionId: groupClass.sessionId, leftAt: null },
      { leftAt: new Date(), connectionState: 'DISCONNECTED' }
    );
    
    // Notify all participants
    io.to(groupClass.sessionId).emit('class_ended', {
      classId: groupClass._id.toString(),
      sessionId: groupClass.sessionId
    });
    
    res.json({ success: true, message: 'Class ended successfully' });
  } catch (error) {
    console.error('End group class error:', error);
    res.status(500).json({ error: 'Failed to end class' });
  }
});

// Join group class (student)
app.post('/api/student/group-classes/:id/join', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const groupClass = await GroupClass.findById(req.params.id);
    if (!groupClass) {
      return res.status(404).json({ error: 'Class not found' });
    }
    
    // Check if class is live
    if (groupClass.status !== 'LIVE') {
      return res.status(400).json({ error: 'Class is not live' });
    }
    
    // Check if student is linked to the teacher
    const isLinked = await ensureTeacherOwnsStudent(groupClass.teacherId, req.userId);
    if (!isLinked) {
      return res.status(403).json({ error: 'Not authorized to join this class' });
    }
    
    // Check if student is enrolled (for non-all-students classes)
    if (!groupClass.isForAllStudents && !groupClass.studentIds.some(id => id.toString() === req.userId)) {
      return res.status(403).json({ error: 'Not enrolled in this class' });
    }
    
    // ✅ FIX: Use findOneAndUpdate with upsert to handle rejoining
    const participant = await GroupCallParticipant.findOneAndUpdate(
      { sessionId: groupClass.sessionId, userId: req.userId },
      {
        role: 'PARTICIPANT',
        socketId: connectedUsers.get(req.userId),
        connectionState: 'CONNECTED',
        isVideoEnabled: false,
        isAudioEnabled: false,
        isScreenSharing: false,
        isHandRaised: false,
        isVideoMutedByHost: false,
        isAudioMutedByHost: false,
        joinedAt: new Date(),
        leftAt: null  // Clear leftAt in case of rejoin
      },
      { upsert: true, new: true }
    );
    
    console.log(`✅ Student ${req.userId} joined class ${groupClass._id} (session: ${groupClass.sessionId})`);
    
    res.json({
      success: true,
      sessionId: groupClass.sessionId,
      classId: groupClass._id.toString(),
      teacherId: groupClass.teacherId.toString(),
      title: groupClass.title,
      subject: groupClass.subject,
      settings: {
        allowStudentVideo: groupClass.allowStudentVideo,
        allowStudentAudio: groupClass.allowStudentAudio,
        allowChat: groupClass.allowChat,
        allowScreenShare: groupClass.allowScreenShare,
        allowWhiteboard: groupClass.allowWhiteboard
      },
      duration: groupClass.duration,
      startedAt: groupClass.startedAt,
      message: 'Successfully joined class'
    });
  } catch (error) {
    console.error('Join group class error:', error);
    res.status(500).json({ error: 'Failed to join class' });
  }
});

// Get class details
app.get('/api/group-classes/:sessionId', authRequired, async (req, res) => {
  try {
    const groupClass = await GroupClass.findOne({ sessionId: req.params.sessionId })
      .populate('teacherId', 'name avatar')
      .lean();
    
    if (!groupClass) {
      return res.status(404).json({ error: 'Class not found' });
    }
    
    // Get participants
    const participants = await GroupCallParticipant.find({ 
      sessionId: req.params.sessionId,
      connectionState: 'CONNECTED'
    })
    .populate('userId', 'name avatar role')
    .lean();
    
    res.json({
      success: true,
      class: {
        id: groupClass._id.toString(),
        title: groupClass.title,
        subject: groupClass.subject,
        teacher: {
          id: groupClass.teacherId._id.toString(),
          name: groupClass.teacherId.name,
          avatar: groupClass.teacherId.avatar
        },
        status: groupClass.status,
        settings: {
          allowStudentVideo: groupClass.allowStudentVideo,
          allowStudentAudio: groupClass.allowStudentAudio,
          allowChat: groupClass.allowChat,
          allowScreenShare: groupClass.allowScreenShare,
          allowWhiteboard: groupClass.allowWhiteboard
        },
        participants: participants.map(p => ({
          userId: p.userId._id.toString(),
          name: p.userId.name,
          avatar: p.userId.avatar,
          role: p.role,
          isVideoEnabled: p.isVideoEnabled,
          isAudioEnabled: p.isAudioEnabled,
          isScreenSharing: p.isScreenSharing,
          isHandRaised: p.isHandRaised
        }))
      }
    });
  } catch (error) {
    console.error('Get class details error:', error);
    res.status(500).json({ error: 'Failed to fetch class details' });
  }
});

// ========= CATCH-ALL ROUTE =========
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method
  });
});

// ========= ERROR HANDLER =========
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// ========= START SERVER =========
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/health`);
  console.log(`📊 API Base: http://localhost:${PORT}/api`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('✅ Process terminated');
    mongoose.connection.close(false, () => {
      console.log('📦 MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('👋 SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('✅ Process terminated');
    mongoose.connection.close(false, () => {
      console.log('📦 MongoDB connection closed');
      process.exit(0);
    });
  });
});
