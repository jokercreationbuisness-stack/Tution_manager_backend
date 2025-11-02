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
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|xls|xlsx|txt|zip/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
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
  createdAt: { type: Date, default: Date.now }
});

// Teacher-Student Link
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
  type: { type: String, enum: ['TEXT', 'IMAGE', 'FILE', 'PDF'], default: 'TEXT' },
  fileUrl: { type: String },
  fileName: { type: String },
  fileSize: { type: Number },
  mimeType: { type: String },
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
    type: { type: String, enum: ['TEXT', 'IMAGE', 'FILE', 'PDF'], default: 'TEXT' }
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

// ========= WEBRTC HELPER FUNCTION =========
async function checkCallAuthorization(callerId, receiverId) {
  try {
    console.log(🔍 Authorization check: Caller=${callerId}, Receiver=${receiverId} );
    
    const caller = await User.findById(callerId);
    const receiver = await User.findById(receiverId);
    
    console.log(👤 Caller: ${caller?.name} (${caller?.role}) );
    console.log(👤 Receiver: ${receiver?.name} (${receiver?.role}) );
    
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
      console.log(🔗 Teacher→Student link: ${link ? 'FOUND' : 'NOT FOUND'} );
      return !!link;
    }
    
    // Student calling teacher
    if (caller.role === 'STUDENT' && receiver.role === 'TEACHER') {
      const link = await TeacherStudentLink.findOne({
        teacherId: receiverId,
        studentId: callerId,
        isActive: true
      });
      console.log(🔗 Student→Teacher link: ${link ? 'FOUND' : 'NOT FOUND'} );
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
    return res.status(403).json({ error: Access denied. Requires ${role} role.  });
  }
  next();
};

  // ========= ADD THIS AFTER authenticate HANDLER =========
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
      
      console.log(📬 Found ${notifications.length} pending notifications for user ${userId} );
      
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
      
      console.log(✅ Sent ${notifications.length} pending notifications );
    } catch (error) {
      console.error('❌ Error fetching pending notifications:', error);
    }
  });

// ========= SOCKET.IO FOR REAL-TIME =========
const connectedUsers = new Map();
const activeCalls = new Map(); // Track active calls
const onlineUsers = new Map(); // For WebRTC calls

io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);

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
      onlineUsers.set(socket.userId, socket.id); // For WebRTC
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

  socket.on('join_conversation', (conversationId) => {
    if (!socket.userId) {
      socket.emit('error', { error: 'Authentication required' });
      return;
    }
    socket.join(conversation_${conversationId} );
  });

  socket.on('leave_conversation', (conversationId) => {
    socket.leave(conversation_${conversationId} );
  });

    socket.on('send_message', async (data) => {
    try {
      const { conversationId, receiverId, content, type, iv, tempId, replyTo } = data;
      
      if (!socket.userId) {
        socket.emit('message_error', { error: 'Not authenticated', tempId });
        return;
      }

      if (!conversationId || !receiverId || !content) {
        socket.emit('message_error', { 
          error: 'Missing required fields',
          tempId 
        });
        return;
      }

      const conversation = await Conversation.findById(conversationId);
      if (!conversation) {
        socket.emit('message_error', { error: 'Conversation not found', tempId });
        return;
      }

      if (conversation.teacherId.toString() !== socket.userId && 
          conversation.studentId.toString() !== socket.userId) {
        socket.emit('message_error', { error: 'Not authorized', tempId });
        return;
      }

      // Build message data
      const messageData = {
        conversationId,
        senderId: socket.userId,
        receiverId,
        content,
        type: type || 'TEXT',
        iv,
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

      const message = await Message.create(messageData);

      await Conversation.findByIdAndUpdate(conversationId, {
        lastMessage: type === 'TEXT' ? content.substring(0, 100) : Sent a ${type?.toLowerCase() || 'file'} ,
        lastMessageAt: new Date(),
        lastMessageSenderId: socket.userId,
        $inc: {
          unreadCountTeacher: socket.role === 'STUDENT' ? 1 : 0,
          unreadCountStudent: socket.role === 'TEACHER' ? 1 : 0
        }
      });

      const populatedMessage = await Message.findById(message._id)
        .populate('senderId', 'name avatar role')
        .lean();

      const messagePayload = {
        ...populatedMessage,
        id: populatedMessage._id.toString()
      };

            io.to(conversation_${conversationId} ).emit('new_message', messagePayload);
      
      // ========= ADD OFFLINE CHECK =========
      const receiverSocketId = connectedUsers.get(receiverId.toString());
      if (receiverSocketId) {
        // User is ONLINE - send immediately
        io.to(receiverId.toString()).emit('new_message', messagePayload);
        
        await Message.findByIdAndUpdate(message._id, {
          delivered: true,
          deliveredAt: new Date()
        });
        
        io.to(conversation_${conversationId} ).emit('message_delivered', {
          messageId: message._id.toString()
        });
      } else {
        // User is OFFLINE - store notification
        const sender = await User.findById(socket.userId);
        await PendingNotification.create({
          userId: receiverId,
          type: 'message',
          senderName: sender.name,
          senderId: socket.userId,
          senderAvatar: sender.avatar,
          conversationId: conversationId,
          content: content
        });
        console.log(📧 Stored pending notification for OFFLINE user ${receiverId} );
      }

      // Remove the old code below (lines with connectedUsers.has check)

  socket.on('mark_read', async (data) => {
    try {
      const { messageId, conversationId } = data;
      
      if (!socket.userId) return;

      await Message.findByIdAndUpdate(messageId, {
        read: true,
        readAt: new Date()
      });

      if (socket.role === 'TEACHER') {
        await Conversation.findByIdAndUpdate(conversationId, {
          unreadCountTeacher: 0
        });
      } else {
        await Conversation.findByIdAndUpdate(conversationId, {
          unreadCountStudent: 0
        });
      }

      io.to(conversation_${conversationId} ).emit('message_read', { 
        messageId,
        readBy: socket.userId 
      });

    } catch (error) {
      console.error('❌ Mark read error:', error);
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
    io.to(receiverId.toString()).emit('user_typing', { 
      conversationId, 
      userId: socket.userId 
    });
  });

  socket.on('stop_typing', (data) => {
    const { conversationId, receiverId } = data;
    if (!socket.userId) return;
    io.to(receiverId.toString()).emit('user_stop_typing', { 
      conversationId, 
      userId: socket.userId 
    });
  });

  // ========= WEBRTC SIGNALING FOR VOICE/VIDEO CALLS =========
  socket.on('call-user', async (data) => {
    try {
      const { receiverId, callType, offer } = data;
      const callerId = socket.userId;
      
      if (!callerId || !receiverId) {
        socket.emit('call-error', { error: 'Invalid call data' });
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
      if (!receiverSocketId) {
        socket.emit('call-error', { error: 'User offline' });
        return;
      }
      
      // Send call notification to receiver
      io.to(receiverSocketId).emit('call-made', {
        callerId: callerId,
        callerName: caller.name,
        callerAvatar: caller.avatar,
        callType: callType,
        offer: offer
      });
      
      // Notify caller that call is ringing
      socket.emit('call-ringing');
      
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

  socket.on('disconnect', async (reason) => {
    console.log(🔌 User disconnected: ${socket.id}, Reason: ${reason} );
    
    // Handle active calls on disconnect
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
    
    if (socket.userId) {
      connectedUsers.delete(socket.userId);
      onlineUsers.delete(socket.userId);
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

  socket.on('error', (error) => {
    console.error('❌ Socket error:', error);
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
      You have successfully registered as a ${role.toLowerCase()}. ,
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

    console.log(✅ Account deleted: ${user.email} (${role}) );
    res.status(204).send();
  } catch (error) {
    console.error('Account deletion error:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// ========= TEACHER-STUDENT LINK ENDPOINTS =========
app.post('/api/teacher/link-student', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Student code is required' });
    }

    const student = await User.findOne({ 
      studentCode: code, 
      role: 'STUDENT', 
      isActive: true 
    });

    if (!student) {
      return res.status(404).json({ error: 'Student not found with this code' });
    }

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

    const deactivatedLink = await TeacherStudentLink.findOne({
      teacherId: req.userId,
      studentId: student._id,
      isActive: false
    });

    if (deactivatedLink) {
      deactivatedLink.isActive = true;
      deactivatedLink.linkedAt = new Date();
      await deactivatedLink.save();
    } else {
      await TeacherStudentLink.create({
        teacherId: req.userId,
        studentId: student._id,
        isActive: true,
        linkedAt: new Date()
      });
    }

    const teacher = await User.findById(req.userId);
    await createNotification(
      student._id,
      'SYSTEM',
      'New Teacher Connection',
      ${teacher.name} has linked you as their student ,
      { teacherId: req.userId }
    );

    const linkCount = await TeacherStudentLink.countDocuments({
      studentId: student._id,
      isActive: true
    });

    console.log(✅ Teacher ${teacher.email} linked student ${student.email} (Student now has ${linkCount} teachers) );

    res.status(200).json({ 
      success: true, 
      message: Successfully linked ${student.name}  
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
      ${teacher.name} has removed you from their student list ,
      { teacherId }
    );

    console.log(✅ Teacher ${teacher.email} unlinked student ${studentId} );
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
          Your teacher added a new class: ${subject} ,
          { classId: newClass._id }
        );
      }
    } else if (scope === 'INDIVIDUAL' && studentId) {
      await createNotification(
        studentId,
        'CLASS',
        'New Class Added',
        Your teacher added a new class: ${subject} ,
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
          New assignment: ${title} ,
          { assignmentId: assignment._id }
        );
      }
    } else if (scope === 'INDIVIDUAL' && studentId) {
      await createNotification(
        studentId,
        'ASSIGNMENT',
        'New Individual Assignment',
        New individual assignment: ${title} ,
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
      Your assignment "${submission.assignmentId.title}" has been graded. ,
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
          New note: ${title} ,
          { noteId: note._id }
        );
      }
    } else if (scope === 'INDIVIDUAL' && studentId) {
      await createNotification(
        studentId,
        'CLASS',
        'New Note Added',
        New note: ${title} ,
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
          New exam: ${title} ,
          { examId: exam._id }
        );
      }
    } else if (scope === 'INDIVIDUAL' && studentId) {
      await createNotification(
        studentId,
        'EXAM',
        'New Individual Exam',
        New individual exam: ${title} ,
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
      Result published for: ${examTitle} ,
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
        return res.status(403).json({ error: Not linked to student ${mark.studentId}  });
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
    
    const blocks = await UserBlock.find({ blockerId: userId }).select('blockedId');
    const blockedUserIds = blocks.map(block => block.blockedId.toString());
    
    let query = {};
    if (role === 'TEACHER') {
      query.teacherId = userId;
      if (blockedUserIds.length > 0) {
        query.studentId = { $nin: blockedUserIds };
      }
    } else {
      query.studentId = userId;
      if (blockedUserIds.length > 0) {
        query.teacherId = { $nin: blockedUserIds };
      }
    }
    
    const conversations = await Conversation.find(query)
      .populate('teacherId', 'name avatar email isOnline lastSeen')
      .populate('studentId', 'name avatar email studentCode isOnline lastSeen')
      .populate('lastMessageSenderId', 'name role')
      .sort({ lastMessageAt: -1 })
      .lean();
    
    const formatted = conversations.map(conv => ({
      id: conv._id.toString(),
      teacher: {
        id: conv.teacherId._id.toString(),
        name: conv.teacherId.name,
        avatar: conv.teacherId.avatar,
        email: conv.teacherId.email,
        isOnline: conv.teacherId.isOnline,
        lastSeen: conv.teacherId.lastSeen
      },
      student: {
        id: conv.studentId._id.toString(),
        name: conv.studentId.name,
        avatar: conv.studentId.avatar,
        email: conv.studentId.email,
        studentCode: conv.studentId.studentCode,
        isOnline: conv.studentId.isOnline,
        lastSeen: conv.studentId.lastSeen
      },
      otherUser: role === 'TEACHER' ? {
        id: conv.studentId._id.toString(),
        name: conv.studentId.name,
        avatar: conv.studentId.avatar,
        role: 'STUDENT',
        isOnline: conv.studentId.isOnline,
        lastSeen: conv.studentId.lastSeen
      } : {
        id: conv.teacherId._id.toString(),
        name: conv.teacherId.name,
        avatar: conv.teacherId.avatar,
        role: 'TEACHER',
        isOnline: conv.teacherId.isOnline,
        lastSeen: conv.teacherId.lastSeen
      },
      lastMessage: conv.lastMessage,
      lastMessageAt: conv.lastMessageAt,
      lastMessageSender: conv.lastMessageSenderId?.name,
      unreadCount: role === 'TEACHER' ? conv.unreadCountTeacher : conv.unreadCountStudent,
      createdAt: conv.createdAt
    }));
    
    res.json({ success: true, conversations: formatted });
  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).json({ error: 'Failed to fetch conversations' });
  }
});

app.get('/api/chat/conversations/:id/messages', authRequired, async (req, res) => {
  try {
    const conversationId = req.params.id;
    const { page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;
    
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    
    if (conversation.teacherId.toString() !== req.userId && conversation.studentId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    const messages = await Message.find({
      conversationId,
      deletedForUsers: { $ne: req.userId }
    })
    .populate('senderId', 'name avatar role')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(parseInt(limit))
    .lean();
    
    // ✅ FIXED: Include replyTo in response
    const formatted = messages.map(msg => ({
      id: msg._id.toString(),
      content: msg.content,
      type: msg.type,
      fileUrl: msg.fileUrl,
      fileName: msg.fileName,
      fileSize: msg.fileSize,
      sender: {
        id: msg.senderId._id.toString(),
        name: msg.senderId.name,
        avatar: msg.senderId.avatar,
        role: msg.senderId.role
      },
      replyTo: msg.replyTo || null,  // ← ADD THIS LINE
      delivered: msg.delivered,
      read: msg.read,
      createdAt: msg.createdAt,
      deleted: msg.deleted
    })).reverse();
    
    res.json({ success: true, messages: formatted });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.post('/api/chat/upload-file', authRequired, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const fileUrl = ${req.protocol}://${req.get('host')}/uploads/${req.file.filename} ;
    
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

app.delete('/api/chat/messages/:id', authRequired, async (req, res) => {
  try {
    const messageId = req.params.id;
    const { deleteForEveryone } = req.body;
    const userId = req.userId;
    
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    if (deleteForEveryone) {
      if (message.senderId.toString() !== userId) {
        return res.status(403).json({ error: 'You can only delete your own messages for everyone' });
      }
      
      message.deleted = true;
      message.deletedAt = new Date();
      message.deletedBy = userId;
      await message.save();
      
      io.to(conversation_${message.conversationId} ).emit('message_deleted', {
        messageId: messageId,
        deletedForEveryone: true
      });
      
      res.json({ success: true, message: 'Message deleted for everyone' });
    } else {
      if (!message.deletedForUsers) {
        message.deletedForUsers = [];
      }
      
      if (!message.deletedForUsers.includes(userId)) {
        message.deletedForUsers.push(userId);
        await message.save();
      }
      
      res.json({ success: true, message: 'Message deleted' });
    }
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

app.delete('/api/chat/conversations/:id/messages', authRequired, async (req, res) => {
  try {
    const conversationId = req.params.id;
    const userId = req.userId;
    
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    
    if (conversation.teacherId.toString() !== userId && conversation.studentId.toString() !== userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    await Message.updateMany(
      { conversationId: conversationId },
      { $addToSet: { deletedForUsers: userId } }
    );
    
    res.json({ success: true, message: 'All messages deleted' });
  } catch (error) {
    console.error('Delete all messages error:', error);
    res.status(500).json({ error: 'Failed to delete messages' });
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

app.patch('/api/chat/messages/:id/delete-for-me', authRequired, async (req, res) => {
  try {
    const messageId = req.params.id;
    const userId = req.userId;
    
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    if (!message.deletedForUsers) {
      message.deletedForUsers = [];
    }
    
    if (!message.deletedForUsers.includes(userId)) {
      message.deletedForUsers.push(userId);
      await message.save();
    }
    
    res.json({ success: true, message: 'Message deleted for you' });
  } catch (error) {
    console.error('Delete message for me error:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

app.delete('/api/chat/conversations/:id', authRequired, async (req, res) => {
  try {
    const conversationId = req.params.id;
    const userId = req.userId;
    const role = req.role;
    
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    
    if (conversation.teacherId.toString() !== userId && conversation.studentId.toString() !== userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    if (role === 'TEACHER') {
      await TeacherStudentLink.findOneAndUpdate(
        { teacherId: userId, studentId: conversation.studentId, isActive: true },
        { isActive: false, unlinkedAt: new Date() }
      );
    }
    
    await Message.updateMany(
      { conversationId: conversationId },
      { $addToSet: { deletedForUsers: userId } }
    );
    
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
    
    const avatarUrl = ${req.protocol}://${req.get('host')}/uploads/${req.file.filename} ;
    
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
      console.log(Created new conversation: ${conversation._id} );
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
    io.to(conversation_${conversation._id} ).emit('new_message', {
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
  console.log(🚀 Server running on port ${PORT} );
  console.log(📱 Environment: ${process.env.NODE_ENV || 'development'} );
  console.log(🌐 Health check: http://localhost:${PORT}/health );
  console.log(📊 API Base: http://localhost:${PORT}/api );
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
