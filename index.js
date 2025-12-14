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
// Add this after your existing requires
const crypto = require('crypto');

// ========= ADD AFTER LINE 18 =========
// Google OAuth & OTP Dependencies
const { OAuth2Client } = require('google-auth-library');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// ========= RESEND EMAIL SERVICE (Unlimited Free Tier) =========
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Generate backup codes for 2FA
const generateBackupCodes = () => {
  const codes = [];
  for (let i = 0; i < 10; i++) {
    codes.push({
      code: crypto.randomBytes(4).toString('hex').toUpperCase(),
      used: false
    });
  }
  return codes;
};

// Send Email OTP via Resend (FREE - unlimited on free tier)
const sendEmailOTP = async (email, otp, purpose) => {
  try {
    const purposeText = {
      'SIGNUP': 'verify your TuitionManager account',
      'RESET_PASSWORD': 'reset your TuitionManager password',
      'LOGIN': 'login to your TuitionManager account'
    };
    
    await resend.emails.send({
      from: 'TuitionManager <onboarding@resend.dev>', // Free tier uses this
      to: email,
      subject: `Your OTP Code - ${otp}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f5;">
          <div style="max-width: 500px; margin: 40px auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); padding: 32px; text-align: center;">
              <h1 style="color: white; margin: 0; font-size: 28px;">TuitionManager</h1>
              <p style="color: rgba(255,255,255,0.9); margin: 8px 0 0 0; font-size: 14px;">Your Learning Companion</p>
            </div>
            
            <!-- Content -->
            <div style="padding: 40px 32px;">
              <p style="color: #374151; font-size: 16px; margin: 0 0 24px 0;">
                Use this code to ${purposeText[purpose] || 'verify your account'}:
              </p>
              
              <!-- OTP Box -->
              <div style="background: linear-gradient(135deg, #EEF2FF 0%, #E0E7FF 100%); border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px;">
                <span style="font-size: 40px; font-weight: bold; letter-spacing: 12px; color: #4F46E5; font-family: 'Courier New', monospace;">${otp}</span>
              </div>
              
              <!-- Warning -->
              <div style="background: #FEF3C7; border-left: 4px solid #F59E0B; padding: 12px 16px; border-radius: 0 8px 8px 0; margin-bottom: 24px;">
                <p style="color: #92400E; font-size: 13px; margin: 0;">
                  ⏰ This code expires in <strong>10 minutes</strong>. Don't share it with anyone.
                </p>
              </div>
              
              <p style="color: #6B7280; font-size: 14px; margin: 0;">
                If you didn't request this code, please ignore this email.
              </p>
            </div>
            
            <!-- Footer -->
            <div style="background: #F9FAFB; padding: 20px 32px; text-align: center; border-top: 1px solid #E5E7EB;">
              <p style="color: #9CA3AF; font-size: 12px; margin: 0;">
                © ${new Date().getFullYear()} TuitionManager. All rights reserved.
              </p>
            </div>
          </div>
        </body>
        </html>
      `
    });
    
    console.log(`📧 Email OTP sent to ${email}`);
    return { success: true };
  } catch (error) {
    console.error('Email send error:', error);
    return { success: false, error: error.message };
  }
};

// Verify Google Token
const verifyGoogleToken = async (idToken) => {
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: GOOGLE_CLIENT_ID
    });
    return ticket.getPayload();
  } catch (error) {
    console.error('Google token verification error:', error);
    return null;
  }
};

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'YOUR_GOOGLE_CLIENT_SECRET';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);



// Jitsi JWT Configuration - Add these environment variables or use defaults
const JITSI_APP_ID = process.env.JITSI_APP_ID || 'tuition_manager_app';
const JITSI_APP_SECRET = process.env.JITSI_APP_SECRET || 'your_jitsi_app_secret_key_2024';

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
  // Add to UserSchema (after subscriptionExpiry field):
  googleId: { type: String, unique: true, sparse: true },
  isGoogleUser: { type: Boolean, default: false },
  isEmailVerified: { type: Boolean, default: false },
  isMobileVerified: { type: Boolean, default: false },
  twoFactorEnabled: { type: Boolean, default: false },
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

// ========= OTP SCHEMA =========
const OTPSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User' },
  email: { type: String },
  mobile: { type: String },
  otp: { type: String, required: true },
  type: { type: String, enum: ['EMAIL', 'SMS', 'BOTH'], required: true },
  purpose: { type: String, enum: ['SIGNUP', 'LOGIN', 'RESET_PASSWORD', '2FA_SETUP'], required: true },
  verified: { type: Boolean, default: false },
  attempts: { type: Number, default: 0 },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});
OTPSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // Auto-delete expired
OTPSchema.index({ email: 1, purpose: 1 });
OTPSchema.index({ mobile: 1, purpose: 1 });

// ========= GOOGLE AUTH PENDING USER SCHEMA =========
const GooglePendingUserSchema = new Schema({
  googleId: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  name: { type: String, required: true },
  avatar: { type: String },
  pendingToken: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});
GooglePendingUserSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ========= TWO FACTOR AUTH SCHEMA =========
const TwoFactorAuthSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true, unique: true },
  secret: { type: String, required: true },
  isEnabled: { type: Boolean, default: false },
  backupCodes: [{
    code: { type: String },
    used: { type: Boolean, default: false }
  }],
  enabledAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

// ========= PASSWORD RESET TOKEN SCHEMA =========
const PasswordResetSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true, unique: true },
  otpVerified: { type: Boolean, default: false },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});
PasswordResetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ========= TEACHER INVITE LINK SCHEMA =========
// Location: Add after UserBlockSchema definition (around line 390)

const TeacherInviteLinkSchema = new Schema({
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, unique: true },
  inviteCode: { type: String, required: true, unique: true }, // 8 char unique code
  inviteLink: { type: String }, // Full URL
  qrCodeData: { type: String }, // Base64 QR code image (optional, can generate on client)
  autoApprove: { type: Boolean, default: false }, // If true, auto-accept requests
  isActive: { type: Boolean, default: true },
  totalScans: { type: Number, default: 0 },
  totalJoins: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
TeacherInviteLinkSchema.index({ inviteCode: 1 });
TeacherInviteLinkSchema.index({ teacherId: 1 });

// ========= LINK REQUEST SCHEMA =========
const LinkRequestSchema = new Schema({
  // Who is requesting
  requesterId: { type: Types.ObjectId, ref: 'User', required: true },
  requesterRole: { type: String, enum: ['STUDENT', 'TEACHER'], required: true },
  
  // Who is being requested (target)
  targetId: { type: Types.ObjectId, ref: 'User', required: true },
  targetRole: { type: String, enum: ['STUDENT', 'TEACHER'], required: true },
  
  // Request details
  inviteCode: { type: String }, // If via invite link
  studentCode: { type: String }, // If via student code (old method)
  requestMethod: { type: String, enum: ['INVITE_LINK', 'STUDENT_CODE', 'DIRECT'], default: 'DIRECT' },
  
  // Status
  status: { type: String, enum: ['PENDING', 'APPROVED', 'REJECTED', 'BLOCKED'], default: 'PENDING' },
  
  // Response info
  respondedAt: { type: Date },
  responseNote: { type: String },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) } // 7 days
});
LinkRequestSchema.index({ targetId: 1, status: 1 });
LinkRequestSchema.index({ requesterId: 1, targetId: 1 }, { unique: true });
LinkRequestSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // Auto-delete expired

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
// Group Class Schema - UPDATED
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
  teacherInClass: { type: Boolean, default: false },
  teacherJoinedAt: { type: Date },
  // Settings
  allowStudentVideo: { type: Boolean, default: true },
  allowStudentAudio: { type: Boolean, default: true },
  allowChat: { type: Boolean, default: true },
  allowScreenShare: { type: Boolean, default: false },
  allowWhiteboard: { type: Boolean, default: true },
  muteOnJoin: { type: Boolean, default: false }, // NEW: Mute students when they join
  recordSession: { type: Boolean, default: false },
  // Status
  status: { type: String, enum: ['SCHEDULED', 'LIVE', 'ENDED', 'CANCELLED'], default: 'SCHEDULED' },
  startedAt: { type: Date },
  endedAt: { type: Date },
  sessionId: { type: String, unique: true, sparse: true },
  recordingUrl: { type: String },
  colorHex: { type: String, default: '#10B981' },
  notes: { type: String },
  // Waiting room
  waitingRoom: [{
    userId: { type: Types.ObjectId, ref: 'User' },
    joinedAt: { type: Date, default: Date.now }
}],
  // Join timing (minutes before scheduled time when join is allowed)
  joinWindowMinutes: { type: Number, default: 10 },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

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

// ========= JITSI GROUP CALL SCHEMAS =========

// Jitsi Room Schema - Teacher creates rooms
const JitsiRoomSchema = new Schema({
  roomId: { type: String, required: true, unique: true }, // Unique Jitsi room identifier
  roomName: { type: String, required: true },
  teacherId: { type: Types.ObjectId, ref: 'User', required: true, index: true },
  settings: {
    allowMicStudents: { type: Boolean, default: true },
    allowCameraStudents: { type: Boolean, default: true },
    allowScreenShareStudents: { type: Boolean, default: false },
    allowChat: { type: Boolean, default: true },
    allowRaiseHand: { type: Boolean, default: true },
    muteAllOnJoin: { type: Boolean, default: false }
  },
  isActive: { type: Boolean, default: false }, // Room is live when true
  scheduledAt: { type: Date },
  startedAt: { type: Date },
  endedAt: { type: Date },
  maxParticipants: { type: Number, default: 50 },
  sectionId: { type: Types.ObjectId, ref: 'Section' },
  studentIds: [{ type: Types.ObjectId, ref: 'User' }], // Specific students allowed
  isForAllStudents: { type: Boolean, default: false },
  jitsiDomain: { type: String, default: 'meet.jit.si' }, // Can be custom Jitsi server
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
JitsiRoomSchema.index({ teacherId: 1, isActive: 1 });
JitsiRoomSchema.index({ roomId: 1 });

// Jitsi Enrollment Schema - Track who can join and kick status
const JitsiEnrollmentSchema = new Schema({
  roomId: { type: String, required: true, index: true },
  
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  role: { type: String, enum: ['TEACHER', 'STUDENT'], required: true },
  kicked: { type: Boolean, default: false },
  kickedAt: { type: Date },
  kickedBy: { type: Types.ObjectId, ref: 'User' },
  kickReason: { type: String },
  mutedByHost: { type: Boolean, default: false },
  videoDisabledByHost: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
JitsiEnrollmentSchema.index({ roomId: 1, oderId: 1 }, { unique: true });

// Jitsi Attendance Schema - Track join/leave with timestamps
const JitsiAttendanceSchema = new Schema({
  roomId: { type: String, required: true, index: true },
  userId: { type: Types.ObjectId, ref: 'User', required: true },  // ← Fix here
  userName: { type: String },
  role: { type: String, enum: ['TEACHER', 'STUDENT'], required: true },
  sessions: [{
    joinTime: { type: Date, required: true },
    leaveTime: { type: Date },
    duration: { type: Number, default: 0 } // Duration in seconds
  }],
  firstJoin: { type: Date },
  lastLeave: { type: Date },
  totalDuration: { type: Number, default: 0 }, // Total seconds across all sessions
  joinCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
JitsiEnrollmentSchema.index({ roomId: 1, userId: 1 }, { unique: true });

// ========= JITSI MODELS =========
const JitsiRoom = mongoose.model('JitsiRoom', JitsiRoomSchema);
const JitsiEnrollment = mongoose.model('JitsiEnrollment', JitsiEnrollmentSchema);
const JitsiAttendance = mongoose.model('JitsiAttendance', JitsiAttendanceSchema);

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

// ========= ADMIN PANEL SCHEMAS =========

// Admin User Schema
const AdminUserSchema = new Schema({
  email: { type: String, required: true, lowercase: true, unique: true },
  passwordHash: { type: String, required: true },
  name: { type: String, required: true, trim: true },
  role: { 
    type: String, 
    enum: ['SUPER_ADMIN', 'ADMIN', 'MODERATOR', 'SUPPORT'], 
    required: true 
  },
  permissions: [{
    type: String,
    enum: [
      'VIEW_DASHBOARD', 'VIEW_USERS', 'EDIT_USERS', 'DELETE_USERS',
      'VIEW_ANALYTICS', 'VIEW_REPORTS', 'EXPORT_DATA',
      'MANAGE_SETTINGS', 'MANAGE_ADMINS', 'VIEW_LOGS',
      'MODERATE_CONTENT', 'VIEW_SUPPORT'
    ]
  }],
  avatar: { type: String },
  isActive: { type: Boolean, default: true },
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String },
  // ===== ADD THESE 2 NEW FIELDS =====
  twoFactorTempSecret: { type: String }, // Temporary secret during 2FA setup
  twoFactorBackupCodes: [{
    code: { type: String },
    used: { type: Boolean, default: false }
  }],
  lastLogin: { type: Date },
  lastLoginIP: { type: String },
  failedLoginAttempts: { type: Number, default: 0 },
  lockedUntil: { type: Date },
  passwordChangedAt: { type: Date, default: Date.now },
  createdBy: { type: Types.ObjectId, ref: 'AdminUser' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
AdminUserSchema.index({ email: 1 });
AdminUserSchema.index({ role: 1 });

// Admin Session Schema (for security tracking)
const AdminSessionSchema = new Schema({
  adminId: { type: Types.ObjectId, ref: 'AdminUser', required: true },
  token: { type: String, required: true, unique: true },
  refreshToken: { type: String, unique: true },
  deviceInfo: { type: String },
  ipAddress: { type: String },
  userAgent: { type: String },
  isActive: { type: Boolean, default: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});
AdminSessionSchema.index({ adminId: 1 });
AdminSessionSchema.index({ token: 1 });
AdminSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Admin Audit Log Schema
const AdminAuditLogSchema = new Schema({
  adminId: { type: Types.ObjectId, ref: 'AdminUser', required: true },
  adminEmail: { type: String, required: true },
  action: { type: String, required: true },
  resource: { type: String, required: true },
  resourceId: { type: String },
  details: { type: Schema.Types.Mixed },
  ipAddress: { type: String },
  userAgent: { type: String },
  status: { type: String, enum: ['SUCCESS', 'FAILED'], default: 'SUCCESS' },
  createdAt: { type: Date, default: Date.now }
});
AdminAuditLogSchema.index({ adminId: 1, createdAt: -1 });
AdminAuditLogSchema.index({ action: 1 });
AdminAuditLogSchema.index({ createdAt: -1 });

// System Settings Schema
const SystemSettingsSchema = new Schema({
  key: { type: String, required: true, unique: true },
  value: { type: Schema.Types.Mixed, required: true },
  category: { type: String, default: 'general' },
  description: { type: String },
  updatedBy: { type: Types.ObjectId, ref: 'AdminUser' },
  updatedAt: { type: Date, default: Date.now }
});


// ========= ADMIN MODELS =========
const AdminUser = mongoose.model('AdminUser', AdminUserSchema);
const AdminSession = mongoose.model('AdminSession', AdminSessionSchema);
const AdminAuditLog = mongoose.model('AdminAuditLog', AdminAuditLogSchema);
const SystemSettings = mongoose.model('SystemSettings', SystemSettingsSchema);

// ========================================
// ========= ENTERPRISE ADMIN SCHEMAS =========
// ========================================

// Push Notification Schema
const PushNotificationSchema = new Schema({
  title: { type: String, required: true },
  body: { type: String, required: true },
  imageUrl: { type: String },
  type: { type: String, enum: ['text', 'image', 'popup', 'in_app'], default: 'text' },
  targetType: { type: String, enum: ['all', 'teachers', 'students', 'specific'], required: true },
  targetUserIds: [{ type: Types.ObjectId, ref: 'User' }],
  data: { type: Schema.Types.Mixed },
  popupSettings: {
    dismissable: { type: Boolean, default: true },
    actionType: { type: String, enum: ['none', 'url', 'screen'], default: 'none' },
    actionUrl: { type: String }
  },
  scheduledAt: { type: Date },
  sentAt: { type: Date },
  status: { type: String, enum: ['draft', 'scheduled', 'sent', 'failed'], default: 'draft' },
  sentCount: { type: Number, default: 0 },
  deliveredCount: { type: Number, default: 0 },
  openedCount: { type: Number, default: 0 },
  createdBy: { type: Types.ObjectId, ref: 'AdminUser' },
  createdAt: { type: Date, default: Date.now }
});
PushNotificationSchema.index({ status: 1, scheduledAt: 1 });

// Support Ticket Schema
const SupportTicketSchema = new Schema({
  ticketNumber: { type: String, unique: true },
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  subject: { type: String, required: true },
  status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
  priority: { type: String, enum: ['low', 'medium', 'high', 'urgent'], default: 'medium' },
  assignedTo: { type: Types.ObjectId, ref: 'AdminUser' },
  lastMessageAt: { type: Date, default: Date.now },
  unreadAdminCount: { type: Number, default: 0 },
  unreadUserCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
SupportTicketSchema.index({ status: 1, priority: 1 });

// Support Message Schema
const SupportMessageSchema = new Schema({
  ticketId: { type: Types.ObjectId, ref: 'SupportTicket', required: true },
  senderId: { type: String, required: true },
  senderType: { type: String, enum: ['user', 'admin'], required: true },
  senderName: { type: String, required: true },
  content: { type: String, required: true },
  attachmentUrl: { type: String },
  attachmentType: { type: String },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
SupportMessageSchema.index({ ticketId: 1, createdAt: 1 });

// Legal Document Schema
const LegalDocumentSchema = new Schema({
  type: { type: String, enum: ['privacy_policy', 'terms_conditions', 'refund_policy', 'cookie_policy', 'gdpr'], required: true, unique: true },
  title: { type: String, required: true },
  content: { type: String, required: true },
  version: { type: String, required: true },
  isPublished: { type: Boolean, default: false },
  publishedAt: { type: Date },
  createdBy: { type: Types.ObjectId, ref: 'AdminUser' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Legal Document Version History
const LegalDocumentVersionSchema = new Schema({
  documentType: { type: String, required: true },
  version: { type: String, required: true },
  content: { type: String, required: true },
  changeLog: { type: String },
  createdBy: { type: Types.ObjectId, ref: 'AdminUser' },
  createdAt: { type: Date, default: Date.now }
});

// Feature Flag Schema
const FeatureFlagSchema = new Schema({
  key: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: { type: String },
  isEnabled: { type: Boolean, default: false },
  targetAudience: { type: String, enum: ['all', 'teachers', 'students', 'percentage'], default: 'all' },
  rolloutPercentage: { type: Number, min: 0, max: 100 },
  category: { type: String, default: 'General' },
  updatedBy: { type: Types.ObjectId, ref: 'AdminUser' },
  updatedAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

// App Configuration Schema
const AppConfigSchema = new Schema({
  key: { type: String, required: true, unique: true },
  value: { type: Schema.Types.Mixed, required: true },
  type: { type: String, enum: ['string', 'number', 'boolean', 'json'], default: 'string' },
  category: { type: String, default: 'General' },
  description: { type: String },
  isSecret: { type: Boolean, default: false },
  updatedBy: { type: Types.ObjectId, ref: 'AdminUser' },
  updatedAt: { type: Date, default: Date.now }
});

// User Block/Ban Schema (Enhanced)
const UserBanSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  reason: { type: String, required: true },
  banType: { type: String, enum: ['temporary', 'permanent'], default: 'temporary' },
  bannedUntil: { type: Date },
  bannedBy: { type: Types.ObjectId, ref: 'AdminUser', required: true },
  unbannedBy: { type: Types.ObjectId, ref: 'AdminUser' },
  unbannedAt: { type: Date },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
UserBanSchema.index({ userId: 1, isActive: 1 });

// User Session Tracking Schema
const UserSessionSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  deviceType: { type: String },
  deviceName: { type: String },
  ipAddress: { type: String },
  location: { type: String },
  userAgent: { type: String },
  isActive: { type: Boolean, default: true },
  lastActivity: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});
UserSessionSchema.index({ userId: 1, isActive: 1 });

// Subscription Plan Schema
const SubscriptionPlanSchema = new Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  currency: { type: String, default: 'INR' },
  duration: { type: String, enum: ['monthly', 'yearly', 'lifetime'], required: true },
  features: [{ type: String }],
  isActive: { type: Boolean, default: true },
  subscriberCount: { type: Number, default: 0 },
  createdBy: { type: Types.ObjectId, ref: 'AdminUser' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// User Subscription Schema
const UserSubscriptionSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  planId: { type: Types.ObjectId, ref: 'SubscriptionPlan', required: true },
  status: { type: String, enum: ['active', 'expired', 'cancelled', 'pending'], default: 'pending' },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  amount: { type: Number, required: true },
  paymentMethod: { type: String },
  transactionId: { type: String },
  createdAt: { type: Date, default: Date.now }
});
UserSubscriptionSchema.index({ userId: 1, status: 1 });

// Transaction Schema
const TransactionSchema = new Schema({
  userId: { type: Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['subscription', 'refund', 'credit'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'INR' },
  status: { type: String, enum: ['completed', 'pending', 'failed', 'refunded'], default: 'pending' },
  paymentMethod: { type: String },
  paymentGatewayId: { type: String },
  orderId: { type: String },
  subscriptionId: { type: Types.ObjectId, ref: 'UserSubscription' },
  metadata: { type: Schema.Types.Mixed },
  createdAt: { type: Date, default: Date.now }
});
TransactionSchema.index({ userId: 1, createdAt: -1 });

// Promo Code Schema
const PromoCodeSchema = new Schema({
  code: { type: String, required: true, unique: true, uppercase: true },
  discountType: { type: String, enum: ['percentage', 'fixed'], default: 'percentage' },
  discountValue: { type: Number, required: true },
  maxUses: { type: Number, default: 100 },
  usedCount: { type: Number, default: 0 },
  validFrom: { type: Date, default: Date.now },
  validUntil: { type: Date, required: true },
  applicablePlans: [{ type: Types.ObjectId, ref: 'SubscriptionPlan' }],
  isActive: { type: Boolean, default: true },
  createdBy: { type: Types.ObjectId, ref: 'AdminUser' },
  createdAt: { type: Date, default: Date.now }
});

// Security Event Schema
const SecurityEventSchema = new Schema({
  eventType: { type: String, required: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
  userId: { type: Types.ObjectId, ref: 'User' },
  adminId: { type: Types.ObjectId, ref: 'AdminUser' },
  ipAddress: { type: String },
  userAgent: { type: String },
  details: { type: Schema.Types.Mixed },
  resolved: { type: Boolean, default: false },
  resolvedBy: { type: Types.ObjectId, ref: 'AdminUser' },
  resolvedAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});
SecurityEventSchema.index({ eventType: 1, createdAt: -1 });

// ========= MODELS =========
const PushNotificationModel = mongoose.model('PushNotification', PushNotificationSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const SupportMessage = mongoose.model('SupportMessage', SupportMessageSchema);
const LegalDocument = mongoose.model('LegalDocument', LegalDocumentSchema);
const LegalDocumentVersion = mongoose.model('LegalDocumentVersion', LegalDocumentVersionSchema);
const FeatureFlag = mongoose.model('FeatureFlag', FeatureFlagSchema);
const AppConfig = mongoose.model('AppConfig', AppConfigSchema);
const UserBan = mongoose.model('UserBan', UserBanSchema);
const UserSession = mongoose.model('UserSession', UserSessionSchema);
const SubscriptionPlan = mongoose.model('SubscriptionPlan', SubscriptionPlanSchema);
const UserSubscription = mongoose.model('UserSubscription', UserSubscriptionSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const PromoCode = mongoose.model('PromoCode', PromoCodeSchema);
const SecurityEvent = mongoose.model('SecurityEvent', SecurityEventSchema);

// ========= LINK REQUEST MODELS =========
const TeacherInviteLink = mongoose.model('TeacherInviteLink', TeacherInviteLinkSchema);
const LinkRequest = mongoose.model('LinkRequest', LinkRequestSchema);

// ========= NEW AUTH MODELS =========
const OTP = mongoose.model('OTP', OTPSchema);
const GooglePendingUser = mongoose.model('GooglePendingUser', GooglePendingUserSchema);
const TwoFactorAuth = mongoose.model('TwoFactorAuth', TwoFactorAuthSchema);
const PasswordReset = mongoose.model('PasswordReset', PasswordResetSchema);

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

// ========= JITSI JWT HELPER FUNCTIONS =========
const generateJitsiJWT = (roomName, userName, userId, isModerator = false, avatarUrl = null) => {
  try {
    const now = Math.floor(Date.now() / 1000);
    
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };
    
    const payload = {
      iss: JITSI_APP_ID,
      aud: 'jitsi',
      exp: now + (2 * 60 * 60), // 2 hours from now
      nbf: now - 10, // 10 seconds ago
      iat: now,
      room: roomName,
      sub: JITSI_APP_ID,
      context: {
        user: {
          id: userId,
          name: userName,
          avatar: avatarUrl,
          moderator: isModerator,
          email: `${userId}@tuitionmanager.app`
        },
        features: {
          livestreaming: isModerator,
          recording: isModerator,
          transcription: false,
          "outbound-call": false,
          "sip-outbound-call": false,
          "sip-inbound-call": false,
          lobby: false // Disable lobby
        }
      }
    };
    
    // If moderator, add additional permissions
    if (isModerator) {
      payload.moderator = true;
      payload.context.user.affiliation = 'owner';
      payload.context.features['kick-out'] = true;
      payload.context.features['mute-everyone'] = true;
      payload.context.features['toggle-lobby'] = true;
    }
    
    const base64UrlEncode = (obj) => {
      return Buffer.from(JSON.stringify(obj))
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    };
    
    const encodedHeader = base64UrlEncode(header);
    const encodedPayload = base64UrlEncode(payload);
    const data = `${encodedHeader}.${encodedPayload}`;
    
    const signature = crypto
      .createHmac('sha256', JITSI_APP_SECRET)
      .update(data)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    
    return `${data}.${signature}`;
  } catch (error) {
    console.error('JWT generation error:', error);
    return null;
  }
};

// ========= ADMIN HELPER FUNCTIONS =========

const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || 'admin_super_secret_key_2024_secure';
const ADMIN_TOKEN_EXPIRY = '8h';
const ADMIN_REFRESH_TOKEN_EXPIRY = '7d';

// ========= UPDATE THIS FUNCTION =========
const getDefaultPermissions = (role) => {
  switch (role) {
    case 'SUPER_ADMIN':
      return [
        'VIEW_DASHBOARD', 'VIEW_USERS', 'EDIT_USERS', 'DELETE_USERS', 'BLOCK_USERS', 'TERMINATE_USERS',
        'VIEW_ANALYTICS', 'VIEW_REPORTS', 'EXPORT_DATA',
        'MANAGE_SETTINGS', 'MANAGE_ADMINS', 'VIEW_LOGS',
        'MODERATE_CONTENT', 'VIEW_SUPPORT', 'REPLY_SUPPORT',
        'SEND_NOTIFICATIONS', 'MANAGE_NOTIFICATIONS',
        'MANAGE_LEGAL', 'PUBLISH_LEGAL',
        'MANAGE_FEATURE_FLAGS', 'MANAGE_APP_CONFIG',
        'MANAGE_SUBSCRIPTIONS', 'MANAGE_TRANSACTIONS', 'ISSUE_REFUNDS',
        'VIEW_SECURITY', 'MANAGE_SECURITY',
        'VIEW_SERVER_STATS', 'MANAGE_MAINTENANCE'
      ];
    case 'ADMIN':
      return [
        'VIEW_DASHBOARD', 'VIEW_USERS', 'EDIT_USERS', 'BLOCK_USERS',
        'VIEW_ANALYTICS', 'VIEW_REPORTS', 'EXPORT_DATA',
        'VIEW_LOGS', 'MODERATE_CONTENT', 
        'VIEW_SUPPORT', 'REPLY_SUPPORT',
        'SEND_NOTIFICATIONS',
        'MANAGE_LEGAL',
        'MANAGE_FEATURE_FLAGS',
        'MANAGE_SUBSCRIPTIONS', 'MANAGE_TRANSACTIONS',
        'VIEW_SECURITY',
        'VIEW_SERVER_STATS'
      ];
    case 'MODERATOR':
      return [
        'VIEW_DASHBOARD', 'VIEW_USERS', 'BLOCK_USERS',
        'MODERATE_CONTENT', 
        'VIEW_SUPPORT', 'REPLY_SUPPORT',
        'SEND_NOTIFICATIONS',
        'VIEW_SECURITY'
      ];
    case 'SUPPORT':
      return [
        'VIEW_DASHBOARD', 'VIEW_USERS',
        'VIEW_SUPPORT', 'REPLY_SUPPORT'
      ];
    default:
      return [];
  }
};

const logAdminAction = async (adminId, adminEmail, action, resource, resourceId, details, req, status = 'SUCCESS') => {
  try {
    await AdminAuditLog.create({
      adminId,
      adminEmail,
      action,
      resource,
      resourceId,
      details,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      status
    });
  } catch (error) {
    console.error('Audit log error:', error);
  }
};

const generateSecureToken = () => {
  return require('crypto').randomBytes(64).toString('hex');
};

// ========= INVITE CODE HELPER FUNCTIONS =========
// Location: Add after generateStudentCode function (around line 630)

const generateInviteCode = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
};

const getInviteLink = (inviteCode) => {
  const baseUrl = process.env.APP_BASE_URL || 'https://tuitionmanager.app';
  return `${baseUrl}/join/${inviteCode}`;
};



// Generate backup codes for 2FA

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
    
    req.userId = decoded.userId;
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

// ========= ADMIN AUTH MIDDLEWARE =========

const adminAuthRequired = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Admin authentication required' });
    }

    const token = authHeader.split(' ')[1];
    
    // Verify JWT
    const decoded = jwt.verify(token, ADMIN_JWT_SECRET);
    
    // Check session exists and is active
    const session = await AdminSession.findOne({ 
      token, 
      adminId: decoded.sub,
      isActive: true,
      expiresAt: { $gt: new Date() }
    });
    
    if (!session) {
      return res.status(401).json({ error: 'Session expired or invalid' });
    }
    
    // Get admin user
    const admin = await AdminUser.findById(decoded.sub);
    if (!admin || !admin.isActive) {
      return res.status(401).json({ error: 'Admin account is deactivated' });
    }
    
    // Check if account is locked
    if (admin.lockedUntil && new Date() < admin.lockedUntil) {
      return res.status(423).json({ 
        error: 'Account is locked',
        lockedUntil: admin.lockedUntil
      });
    }
    
    req.adminId = decoded.sub;
    req.adminRole = admin.role;
    req.adminEmail = admin.email;
    req.adminPermissions = admin.permissions;
    req.sessionId = session._id;
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid admin token' });
  }
};

const requireAdminPermission = (permission) => (req, res, next) => {
  if (!req.adminPermissions.includes(permission)) {
    logAdminAction(req.adminId, req.adminEmail, `PERMISSION_DENIED:${permission}`, 'SECURITY', null, {}, req, 'FAILED');
    return res.status(403).json({ error: `Permission denied: ${permission}` });
  }
  next();
};

const requireAdminRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.adminRole)) {
    return res.status(403).json({ error: `Role required: ${roles.join(' or ')}` });
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
    
    // 🚀 FIX: Use decoded.userId (matches your JWT creation)
    const user = await User.findById(decoded.userId).select('isActive role name email');
    
    if (!user) {
      socket.emit('auth_error', { error: 'User not found' });
      return;
    }
    
    if (!user.isActive) {
      socket.emit('auth_error', { error: 'Account is deactivated' });
      return;
    }

    // 🚀 FIX: Use decoded.userId here too
    socket.userId = decoded.userId;
    socket.role = decoded.role;
    socket.userEmail = user.email;  // Get email from user object, not token
    
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
    
    console.log(`✅ User authenticated: ${user.name} (${socket.userId})`);
    
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

  // Location: Add inside io.on('connection') handler (around line 2800)

// ========= LINK REQUEST SOCKET EVENTS =========

// Join user's personal room for notifications
socket.on('join-personal-room', (userId) => {
  if (userId) {
    socket.join(userId.toString());
    console.log(`👤 User ${userId} joined personal notification room`);
  }
});

// Listen for request count updates
socket.on('get-request-count', async (callback) => {
  try {
    if (socket.userId) {
      const count = await LinkRequest.countDocuments({
        targetId: socket.userId,
        status: 'PENDING'
      });
      if (typeof callback === 'function') {
        callback({ count });
      }
    }
  } catch (error) {
    console.error('Get request count error:', error);
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

    // ========= JITSI GROUP CALL SOCKET EVENTS =========
  
  // Join Jitsi room (Socket room for real-time updates)
  socket.on('jitsi-join-room', async (data) => {
    try {
      const { roomId } = typeof data === 'string' ? JSON.parse(data) : data;
      
      if (!socket.userId) {
        socket.emit('jitsi-error', { error: 'Not authenticated' });
        return;
      }
      
      // Check enrollment and kick status
      const enrollment = await JitsiEnrollment.findOne({
        roomId,
        userId: socket.userId
      });
      
      if (!enrollment) {
        socket.emit('jitsi-error', { error: 'Not enrolled in this class' });
        return;
      }
      
      if (enrollment.kicked) {
        socket.emit('jitsi-kicked', { 
          roomId, 
          reason: enrollment.kickReason || 'You have been removed from this class' 
        });
        return;
      }
      
      const room = await JitsiRoom.findOne({ roomId });
      if (!room || !room.isActive) {
        socket.emit('jitsi-error', { error: 'Class is not active' });
        return;
      }
      
      // Join socket room for real-time updates
      socket.join(`jitsi-${roomId}`);
      
      // Get user info
      const user = await User.findById(socket.userId).select('name avatar');
      
      // Record attendance - join
      let attendance = await JitsiAttendance.findOne({ roomId, userId: socket.userId });
      
      if (!attendance) {
        attendance = await JitsiAttendance.create({
          roomId,
          oderId: socket.userId,
          userName: user?.name,
          role: enrollment.role,
          sessions: [{ joinTime: new Date() }],
          firstJoin: new Date(),
          joinCount: 1
        });
      } else {
        // Add new session
        attendance.sessions.push({ joinTime: new Date() });
        attendance.joinCount += 1;
        attendance.updatedAt = new Date();
        await attendance.save();
      }
      
      console.log(`🎥 User ${socket.userId} joined Jitsi room ${roomId}`);
      
      // Notify others in the room
      socket.to(`jitsi-${roomId}`).emit('jitsi-participant-joined', {
        oderId: socket.userId,
        name: user?.name,
        avatar: user?.avatar,
        role: enrollment.role
      });
      
      // Send current settings and enrollment status
      socket.emit('jitsi-joined', {
        roomId,
        settings: room.settings,
        mutedByHost: enrollment.mutedByHost,
        videoDisabledByHost: enrollment.videoDisabledByHost
      });
    } catch (error) {
      console.error('Jitsi join room error:', error);
      socket.emit('jitsi-error', { error: 'Failed to join room' });
    }
  });
  
  // Leave Jitsi room
  socket.on('jitsi-leave-room', async (data) => {
    try {
      const { roomId } = typeof data === 'string' ? JSON.parse(data) : data;
      
      if (!socket.userId) return;
      
      // Record attendance - leave
      const attendance = await JitsiAttendance.findOne({ roomId, userId: socket.userId });
      
      if (attendance && attendance.sessions.length > 0) {
        const lastSession = attendance.sessions[attendance.sessions.length - 1];
        if (!lastSession.leaveTime) {
          lastSession.leaveTime = new Date();
          lastSession.duration = Math.floor((lastSession.leaveTime - lastSession.joinTime) / 1000);
          attendance.lastLeave = new Date();
          attendance.totalDuration = attendance.sessions.reduce((sum, s) => sum + (s.duration || 0), 0);
          attendance.updatedAt = new Date();
          await attendance.save();
        }
      }
      
      socket.leave(`jitsi-${roomId}`);
      
      console.log(`🎥 User ${socket.userId} left Jitsi room ${roomId}`);
      
      // Notify others
      socket.to(`jitsi-${roomId}`).emit('jitsi-participant-left', {
        userId: socket.userId
      });
    } catch (error) {
      console.error('Jitsi leave room error:', error);
    }
  });
  
  // Teacher updates settings during meeting
  socket.on('jitsi-update-settings', async (data) => {
    try {
      const { roomId, settings } = typeof data === 'string' ? JSON.parse(data) : data;
      
      if (!socket.userId) return;
      
      // Verify teacher
      const room = await JitsiRoom.findOne({ roomId, teacherId: socket.userId });
      if (!room) {
        socket.emit('jitsi-error', { error: 'Only teacher can update settings' });
        return;
      }
      
      room.settings = { ...room.settings, ...settings };
      room.updatedAt = new Date();
      await room.save();
      
      // Broadcast to all in room
      io.to(`jitsi-${roomId}`).emit('jitsi-settings-update', {
        roomId,
        settings: room.settings
      });
      
      console.log(`⚙️ Settings updated for room ${roomId}`);
    } catch (error) {
      console.error('Update settings error:', error);
    }
  });
  
  // Teacher mutes all students
  socket.on('jitsi-mute-all-students', async (data) => {
    try {
      const { roomId } = typeof data === 'string' ? JSON.parse(data) : data;
      
      const room = await JitsiRoom.findOne({ roomId, teacherId: socket.userId });
      if (!room) return;
      
      await JitsiEnrollment.updateMany(
        { roomId, role: 'STUDENT' },
        { mutedByHost: true }
      );
      
      // Update settings to prevent unmuting
      room.settings.allowMicStudents = false;
      await room.save();
      
      io.to(`jitsi-${roomId}`).emit('jitsi-mute-all', { roomId });
      io.to(`jitsi-${roomId}`).emit('jitsi-settings-update', { roomId, settings: room.settings });
      
      console.log(`🔇 All students muted in room ${roomId}`);
    } catch (error) {
      console.error('Mute all error:', error);
    }
  });
  
  // Teacher mutes specific student
  socket.on('jitsi-mute-student', async (data) => {
    try {
      const { roomId, targetUserId } = typeof data === 'string' ? JSON.parse(data) : data;
      
      const room = await JitsiRoom.findOne({ roomId, teacherId: socket.userId });
      if (!room) return;
      
      await JitsiEnrollment.findOneAndUpdate(
        { roomId, userId: targetUserId },
        { mutedByHost: true }
      );
      
      io.to(targetUserId).emit('jitsi-mute-user', { roomId, userId: targetUserId });
      
      console.log(`🔇 Student ${targetUserId} muted in room ${roomId}`);
    } catch (error) {
      console.error('Mute student error:', error);
    }
  });
  
  // Teacher disables video for student
  socket.on('jitsi-disable-student-video', async (data) => {
    try {
      const { roomId, targetUserId } = typeof data === 'string' ? JSON.parse(data) : data;
      
      const room = await JitsiRoom.findOne({ roomId, teacherId: socket.userId });
      if (!room) return;
      
      await JitsiEnrollment.findOneAndUpdate(
        { roomId, userId: targetUserId },
        { videoDisabledByHost: true }
      );
      
      io.to(targetUserId).emit('jitsi-disable-video', { roomId, userId: targetUserId });
    } catch (error) {
      console.error('Disable video error:', error);
    }
  });
  
  // Teacher kicks student
  socket.on('jitsi-kick-student', async (data) => {
    try {
      const { roomId, targetUserId, reason } = typeof data === 'string' ? JSON.parse(data) : data;
      
      const room = await JitsiRoom.findOne({ roomId, teacherId: socket.userId });
      if (!room) return;
      
      await JitsiEnrollment.findOneAndUpdate(
        { roomId, userId: targetUserId },
        { 
          kicked: true, 
          kickedAt: new Date(),
          kickedBy: socket.userId,
          kickReason: reason || 'Removed by teacher'
        }
      );
      
      // Close attendance session
      const attendance = await JitsiAttendance.findOne({ roomId, userId: targetUserId });
      if (attendance) {
        const lastSession = attendance.sessions[attendance.sessions.length - 1];
        if (lastSession && !lastSession.leaveTime) {
          lastSession.leaveTime = new Date();
          lastSession.duration = Math.floor((lastSession.leaveTime - lastSession.joinTime) / 1000);
          attendance.lastLeave = new Date();
          attendance.totalDuration = attendance.sessions.reduce((sum, s) => sum + (s.duration || 0), 0);
          await attendance.save();
        }
      }
      
      io.to(targetUserId).emit('jitsi-kicked', { 
        roomId, 
        userId: targetUserId,
        reason: reason || 'You have been removed from the class'
      });
      
      // Notify others
      io.to(`jitsi-${roomId}`).emit('jitsi-participant-left', { userId: targetUserId });
      
      console.log(`👢 Student ${targetUserId} kicked from room ${roomId}`);
    } catch (error) {
      console.error('Kick student error:', error);
    }
  });
  
  // Student attempts to unmute (for validation)
  socket.on('jitsi-unmute-attempt', async (data) => {
    try {
      const { roomId } = typeof data === 'string' ? JSON.parse(data) : data;
      
      const room = await JitsiRoom.findOne({ roomId });
      const enrollment = await JitsiEnrollment.findOne({ roomId, userId: socket.userId });
      
      if (!room || !enrollment) return;
      
      // Check if student can unmute
      if (enrollment.role === 'STUDENT') {
        if (!room.settings.allowMicStudents || enrollment.mutedByHost) {
          // Force re-mute
          socket.emit('jitsi-force-mute', { roomId, reason: 'Microphone is disabled by teacher' });
        }
      }
    } catch (error) {
      console.error('Unmute attempt error:', error);
    }
  });
  
  // Handle disconnect - close attendance session
  socket.on('disconnect', async () => {
    // ... existing disconnect logic ...
    
    // Close any open Jitsi attendance sessions
    if (socket.userId) {
      try {
        const openAttendances = await JitsiAttendance.find({
          userId: socket.userId,
          'sessions.leaveTime': null
        });
        
        for (const attendance of openAttendances) {
          const lastSession = attendance.sessions[attendance.sessions.length - 1];
          if (lastSession && !lastSession.leaveTime) {
            lastSession.leaveTime = new Date();
            lastSession.duration = Math.floor((lastSession.leaveTime - lastSession.joinTime) / 1000);
            attendance.lastLeave = new Date();
            attendance.totalDuration = attendance.sessions.reduce((sum, s) => sum + (s.duration || 0), 0);
            await attendance.save();
            
            // Notify room
            io.to(`jitsi-${attendance.roomId}`).emit('jitsi-participant-left', {
              userId: socket.userId
            });
          }
        }
      } catch (error) {
        console.error('Error closing Jitsi sessions on disconnect:', error);
      }
    }
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

    // ========= WAITING ROOM SOCKET EVENTS =========
  
  // Student joins waiting room via socket
  socket.on('join-waiting-room', async (data) => {
    try {
      const { classId } = typeof data === 'string' ? JSON.parse(data) : data;
      
      if (!socket.userId) return;
      
      socket.join(`waiting-${classId}`);
      console.log(`⏳ Socket ${socket.userId} joined waiting room for ${classId}`);
      
      // Notify teacher about new student in waiting room
      const groupClass = await GroupClass.findById(classId);
      if (groupClass) {
        const user = await User.findById(socket.userId).select('name');
        io.to(groupClass.teacherId.toString()).emit('student-joined-waiting', {
          classId,
          studentId: socket.userId,
          studentName: user?.name,
          waitingCount: (groupClass.waitingRoom?.length || 0) + 1
        });
      }
    } catch (error) {
      console.error('Join waiting room socket error:', error);
    }
  });

  // Student leaves waiting room via socket
  socket.on('leave-waiting-room', async (data) => {
    try {
      const { classId } = typeof data === 'string' ? JSON.parse(data) : data;
      socket.leave(`waiting-${classId}`);
    } catch (error) {
      console.error('Leave waiting room socket error:', error);
    }
  });
  
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

// ========================================
// ========= INVITE LINK & REQUEST APIs =========
// ========================================
// Location: Add after existing /api/students routes (around line 1200)

// ========= TEACHER INVITE LINK APIs =========

// Generate or get teacher's invite link
app.post('/api/invite/generate', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    let inviteLink = await TeacherInviteLink.findOne({ teacherId: req.userId });
    
    if (!inviteLink) {
      // Generate new invite code
      let inviteCode;
      let isUnique = false;
      
      while (!isUnique) {
        inviteCode = generateInviteCode();
        const existing = await TeacherInviteLink.findOne({ inviteCode });
        if (!existing) isUnique = true;
      }
      
      inviteLink = await TeacherInviteLink.create({
        teacherId: req.userId,
        inviteCode,
        inviteLink: getInviteLink(inviteCode),
        autoApprove: false
      });
      
      console.log(`📎 Generated new invite link for teacher ${req.userId}: ${inviteCode}`);
    }
    
    const teacher = await User.findById(req.userId).select('name');
    
    res.json({
      success: true,
      inviteCode: inviteLink.inviteCode,
      inviteLink: inviteLink.inviteLink,
      autoApprove: inviteLink.autoApprove,
      isActive: inviteLink.isActive,
      totalScans: inviteLink.totalScans,
      totalJoins: inviteLink.totalJoins,
      teacherName: teacher?.name,
      createdAt: inviteLink.createdAt
    });
  } catch (error) {
    console.error('Generate invite link error:', error);
    res.status(500).json({ error: 'Failed to generate invite link' });
  }
});

// Get teacher's invite settings
app.get('/api/invite/settings', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const inviteLink = await TeacherInviteLink.findOne({ teacherId: req.userId });
    
    if (!inviteLink) {
      return res.json({
        success: true,
        hasInviteLink: false,
        autoApprove: false
      });
    }
    
    res.json({
      success: true,
      hasInviteLink: true,
      inviteCode: inviteLink.inviteCode,
      inviteLink: inviteLink.inviteLink,
      autoApprove: inviteLink.autoApprove,
      isActive: inviteLink.isActive,
      totalScans: inviteLink.totalScans,
      totalJoins: inviteLink.totalJoins
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get invite settings' });
  }
});

// Update auto-approve setting
app.put('/api/invite/auto-approve', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { autoApprove } = req.body;
    
    const inviteLink = await TeacherInviteLink.findOneAndUpdate(
      { teacherId: req.userId },
      { autoApprove: autoApprove === true, updatedAt: new Date() },
      { new: true }
    );
    
    if (!inviteLink) {
      return res.status(404).json({ error: 'Invite link not found. Generate one first.' });
    }
    
    console.log(`⚙️ Teacher ${req.userId} set autoApprove to ${autoApprove}`);
    
    res.json({
      success: true,
      autoApprove: inviteLink.autoApprove,
      message: autoApprove ? 'Auto-approve enabled' : 'Manual approval required'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update setting' });
  }
});

// Regenerate invite code
app.post('/api/invite/regenerate', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    let inviteCode;
    let isUnique = false;
    
    while (!isUnique) {
      inviteCode = generateInviteCode();
      const existing = await TeacherInviteLink.findOne({ inviteCode });
      if (!existing) isUnique = true;
    }
    
    const inviteLink = await TeacherInviteLink.findOneAndUpdate(
      { teacherId: req.userId },
      { 
        inviteCode,
        inviteLink: getInviteLink(inviteCode),
        totalScans: 0,
        updatedAt: new Date()
      },
      { new: true, upsert: true }
    );
    
    console.log(`🔄 Regenerated invite code for teacher ${req.userId}: ${inviteCode}`);
    
    res.json({
      success: true,
      inviteCode: inviteLink.inviteCode,
      inviteLink: inviteLink.inviteLink,
      message: 'Invite code regenerated successfully'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to regenerate invite code' });
  }
});

// Toggle invite link active/inactive
app.put('/api/invite/toggle', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const inviteLink = await TeacherInviteLink.findOne({ teacherId: req.userId });
    
    if (!inviteLink) {
      return res.status(404).json({ error: 'Invite link not found' });
    }
    
    inviteLink.isActive = !inviteLink.isActive;
    inviteLink.updatedAt = new Date();
    await inviteLink.save();
    
    res.json({
      success: true,
      isActive: inviteLink.isActive,
      message: inviteLink.isActive ? 'Invite link activated' : 'Invite link deactivated'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to toggle invite link' });
  }
});

// ========= JOIN VIA INVITE CODE APIs =========

// Get teacher info by invite code (for preview before joining)
app.get('/api/invite/preview/:code', authRequired, async (req, res) => {
  try {
    const inviteLink = await TeacherInviteLink.findOne({ 
      inviteCode: req.params.code.toUpperCase(),
      isActive: true
    });
    
    if (!inviteLink) {
      return res.status(404).json({ error: 'Invalid or inactive invite code' });
    }
    
    const teacher = await User.findById(inviteLink.teacherId)
      .select('name avatar');
    
    if (!teacher) {
      return res.status(404).json({ error: 'Teacher not found' });
    }
    
    // Increment scan count
    inviteLink.totalScans += 1;
    await inviteLink.save();
    
    // Check if already linked
    const existingLink = await TeacherStudentLink.findOne({
      teacherId: inviteLink.teacherId,
      studentId: req.userId,
      isActive: true
    });
    
    // Check if request already pending
    const existingRequest = await LinkRequest.findOne({
      requesterId: req.userId,
      targetId: inviteLink.teacherId,
      status: 'PENDING'
    });
    
    res.json({
      success: true,
      teacher: {
        id: teacher._id.toString(),
        name: teacher.name,
        avatar: teacher.avatar
      },
      autoApprove: inviteLink.autoApprove,
      alreadyLinked: !!existingLink,
      requestPending: !!existingRequest
    });
  } catch (error) {
    console.error('Preview invite error:', error);
    res.status(500).json({ error: 'Failed to get invite preview' });
  }
});

// Join via invite code (creates request or auto-joins)
app.post('/api/invite/join/:code', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const inviteCode = req.params.code.toUpperCase();
    
    const inviteLink = await TeacherInviteLink.findOne({ 
      inviteCode,
      isActive: true
    });
    
    if (!inviteLink) {
      return res.status(404).json({ error: 'Invalid or inactive invite code' });
    }
    
    const teacherId = inviteLink.teacherId;
    const studentId = req.userId;
    
    // Check if already linked
    const existingLink = await TeacherStudentLink.findOne({
      teacherId,
      studentId
    });
    
    if (existingLink && existingLink.isActive) {
      return res.status(400).json({ error: 'You are already linked with this teacher' });
    }
    
    // Check if blocked
    const isBlockedByTeacher = await isBlocked(teacherId, studentId);
    if (isBlockedByTeacher) {
      return res.status(403).json({ error: 'Unable to send request to this teacher' });
    }
    
    // Check existing request
    const existingRequest = await LinkRequest.findOne({
      requesterId: studentId,
      targetId: teacherId
    });
    
    if (existingRequest) {
      if (existingRequest.status === 'PENDING') {
        return res.status(400).json({ error: 'Request already pending' });
      }
      if (existingRequest.status === 'BLOCKED') {
        return res.status(403).json({ error: 'You are blocked from sending requests to this teacher' });
      }
      // If rejected, allow resending
      if (existingRequest.status === 'REJECTED') {
        existingRequest.status = 'PENDING';
        existingRequest.createdAt = new Date();
        existingRequest.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        existingRequest.inviteCode = inviteCode;
        existingRequest.requestMethod = 'INVITE_LINK';
        await existingRequest.save();
      }
    }
    
    const student = await User.findById(studentId).select('name avatar studentCode');
    const teacher = await User.findById(teacherId).select('name fcmToken');
    
    // If auto-approve is ON, directly link
    if (inviteLink.autoApprove) {
      // Reactivate or create link
      if (existingLink) {
        existingLink.isActive = true;
        existingLink.linkedAt = new Date();
        existingLink.isBlocked = false;
        await existingLink.save();
      } else {
        await TeacherStudentLink.create({
          teacherId,
          studentId,
          isActive: true
        });
      }
      
      inviteLink.totalJoins += 1;
      await inviteLink.save();
      
      // Create notification for teacher
      await createNotification(
        teacherId,
        'SYSTEM',
        'New Student Joined',
        `${student?.name || 'A student'} joined via your invite link`,
        { studentId: studentId.toString(), type: 'student_joined' }
      );
      
      console.log(`✅ Student ${studentId} auto-joined teacher ${teacherId} via invite link`);
      
      return res.json({
        success: true,
        autoApproved: true,
        message: 'Successfully linked with teacher!',
        teacher: { id: teacherId.toString(), name: teacher?.name }
      });
    }
    
    // Manual approval required - create request
    if (!existingRequest || existingRequest.status === 'REJECTED') {
      await LinkRequest.create({
        requesterId: studentId,
        requesterRole: 'STUDENT',
        targetId: teacherId,
        targetRole: 'TEACHER',
        inviteCode,
        requestMethod: 'INVITE_LINK',
        status: 'PENDING'
      });
    }
    
    // Create notification for teacher
    await createNotification(
      teacherId,
      'SYSTEM',
      'New Link Request',
      `${student?.name || 'A student'} wants to connect with you`,
      { 
        requesterId: studentId.toString(), 
        requesterName: student?.name,
        type: 'link_request' 
      }
    );
    
    // Send real-time notification via socket
    io.to(teacherId.toString()).emit('new_link_request', {
      requesterId: studentId.toString(),
      requesterName: student?.name,
      requesterAvatar: student?.avatar,
      studentCode: student?.studentCode
    });
    
    console.log(`📨 Link request sent from student ${studentId} to teacher ${teacherId}`);
    
    res.json({
      success: true,
      autoApproved: false,
      message: 'Request sent! Waiting for teacher approval.',
      teacher: { id: teacherId.toString(), name: teacher?.name }
    });
  } catch (error) {
    console.error('Join via invite error:', error);
    res.status(500).json({ error: 'Failed to process join request' });
  }
});

// ========= LINK REQUEST MANAGEMENT APIs =========

// Get pending requests (for both teachers and students)
app.get('/api/requests/pending', authRequired, async (req, res) => {
  try {
    const requests = await LinkRequest.find({
      targetId: req.userId,
      status: 'PENDING'
    })
    .populate('requesterId', 'name avatar studentCode role')
    .sort({ createdAt: -1 })
    .lean();
    
    const formatted = requests.map(r => ({
      id: r._id.toString(),
      requester: r.requesterId ? {
        id: r.requesterId._id.toString(),
        name: r.requesterId.name,
        avatar: r.requesterId.avatar,
        studentCode: r.requesterId.studentCode,
        role: r.requesterId.role
      } : null,
      requestMethod: r.requestMethod,
      createdAt: r.createdAt,
      expiresAt: r.expiresAt
    }));
    
    res.json({
      success: true,
      requests: formatted,
      count: formatted.length
    });
  } catch (error) {
    console.error('Get pending requests error:', error);
    res.status(500).json({ error: 'Failed to fetch requests' });
  }
});

// Get all requests with filters
app.get('/api/requests', authRequired, async (req, res) => {
  try {
    const { status, type } = req.query;
    
    const query = {};
    
    if (type === 'received') {
      query.targetId = req.userId;
    } else if (type === 'sent') {
      query.requesterId = req.userId;
    } else {
      // Default: show received requests
      query.targetId = req.userId;
    }
    
    if (status && ['PENDING', 'APPROVED', 'REJECTED', 'BLOCKED'].includes(status)) {
      query.status = status;
    }
    
    const requests = await LinkRequest.find(query)
      .populate('requesterId', 'name avatar studentCode role')
      .populate('targetId', 'name avatar role')
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();
    
    const formatted = requests.map(r => ({
      id: r._id.toString(),
      requester: r.requesterId ? {
        id: r.requesterId._id.toString(),
        name: r.requesterId.name,
        avatar: r.requesterId.avatar,
        studentCode: r.requesterId.studentCode,
        role: r.requesterId.role
      } : null,
      target: r.targetId ? {
        id: r.targetId._id.toString(),
        name: r.targetId.name,
        avatar: r.targetId.avatar,
        role: r.targetId.role
      } : null,
      status: r.status,
      requestMethod: r.requestMethod,
      createdAt: r.createdAt,
      respondedAt: r.respondedAt
    }));
    
    res.json({
      success: true,
      requests: formatted,
      count: formatted.length
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch requests' });
  }
});

// Get request counts (for badge)
app.get('/api/requests/count', authRequired, async (req, res) => {
  try {
    const pendingCount = await LinkRequest.countDocuments({
      targetId: req.userId,
      status: 'PENDING'
    });
    
    res.json({
      success: true,
      pendingCount
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get count' });
  }
});

// Approve request
app.post('/api/requests/:requestId/approve', authRequired, async (req, res) => {
  try {
    const request = await LinkRequest.findOne({
      _id: req.params.requestId,
      targetId: req.userId,
      status: 'PENDING'
    }).populate('requesterId', 'name fcmToken');
    
    if (!request) {
      return res.status(404).json({ error: 'Request not found or already processed' });
    }
    
    // Determine teacher and student based on roles
    let teacherId, studentId;
    if (req.role === 'TEACHER') {
      teacherId = req.userId;
      studentId = request.requesterId._id;
    } else {
      teacherId = request.requesterId._id;
      studentId = req.userId;
    }
    
    // Create or reactivate link
    const existingLink = await TeacherStudentLink.findOne({ teacherId, studentId });
    
    if (existingLink) {
      existingLink.isActive = true;
      existingLink.linkedAt = new Date();
      existingLink.isBlocked = false;
      await existingLink.save();
    } else {
      await TeacherStudentLink.create({
        teacherId,
        studentId,
        isActive: true
      });
    }
    
    // Update request status
    request.status = 'APPROVED';
    request.respondedAt = new Date();
    await request.save();
    
    // Update invite link stats if applicable
    if (request.inviteCode) {
      await TeacherInviteLink.findOneAndUpdate(
        { inviteCode: request.inviteCode },
        { $inc: { totalJoins: 1 } }
      );
    }
    
    // Notify requester
    const approver = await User.findById(req.userId).select('name');
    await createNotification(
      request.requesterId._id,
      'SYSTEM',
      'Request Approved! 🎉',
      `${approver?.name || 'User'} approved your link request`,
      { approverId: req.userId, type: 'request_approved' }
    );
    
    // Real-time notification
    io.to(request.requesterId._id.toString()).emit('request_approved', {
      requestId: request._id.toString(),
      approverName: approver?.name
    });
    
    console.log(`✅ Request ${req.params.requestId} approved by ${req.userId}`);
    
    res.json({
      success: true,
      message: 'Request approved successfully',
      linkedUser: {
        id: request.requesterId._id.toString(),
        name: request.requesterId.name
      }
    });
  } catch (error) {
    console.error('Approve request error:', error);
    res.status(500).json({ error: 'Failed to approve request' });
  }
});

// Reject request
app.post('/api/requests/:requestId/reject', authRequired, async (req, res) => {
  try {
    const { note } = req.body;
    
    const request = await LinkRequest.findOne({
      _id: req.params.requestId,
      targetId: req.userId,
      status: 'PENDING'
    }).populate('requesterId', 'name');
    
    if (!request) {
      return res.status(404).json({ error: 'Request not found or already processed' });
    }
    
    request.status = 'REJECTED';
    request.respondedAt = new Date();
    request.responseNote = note || '';
    await request.save();
    
    // Notify requester
    const rejecter = await User.findById(req.userId).select('name');
    await createNotification(
      request.requesterId._id,
      'SYSTEM',
      'Request Declined',
      `${rejecter?.name || 'User'} declined your link request`,
      { rejecterId: req.userId, type: 'request_rejected' }
    );
    
    io.to(request.requesterId._id.toString()).emit('request_rejected', {
      requestId: request._id.toString()
    });
    
    console.log(`❌ Request ${req.params.requestId} rejected by ${req.userId}`);
    
    res.json({
      success: true,
      message: 'Request rejected'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reject request' });
  }
});

// Block requester (reject + block future requests)
app.post('/api/requests/:requestId/block', authRequired, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const request = await LinkRequest.findOne({
      _id: req.params.requestId,
      targetId: req.userId
    }).populate('requesterId', 'name');
    
    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }
    
    // Update request status
    request.status = 'BLOCKED';
    request.respondedAt = new Date();
    request.responseNote = reason || 'Blocked by user';
    await request.save();
    
    // Add to block list
    await UserBlock.findOneAndUpdate(
      { blockerId: req.userId, blockedId: request.requesterId._id },
      { blockerId: req.userId, blockedId: request.requesterId._id },
      { upsert: true }
    );
    
    // If there's an existing link, deactivate and mark blocked
    await TeacherStudentLink.findOneAndUpdate(
      { 
        $or: [
          { teacherId: req.userId, studentId: request.requesterId._id },
          { teacherId: request.requesterId._id, studentId: req.userId }
        ]
      },
      { isActive: false, isBlocked: true, blockedAt: new Date(), blockedBy: req.role.toLowerCase() }
    );
    
    console.log(`🚫 Request ${req.params.requestId} blocked by ${req.userId}`);
    
    res.json({
      success: true,
      message: 'User blocked. They cannot send you requests anymore.'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to block user' });
  }
});

// Send request directly (teacher adding student via code OR student adding teacher)
app.post('/api/requests/send', authRequired, async (req, res) => {
  try {
    const { targetId, studentCode } = req.body;
    
    let targetUser;
    
    // Find target user
    if (studentCode) {
      targetUser = await User.findOne({ studentCode: studentCode.toUpperCase() });
      if (!targetUser) {
        return res.status(404).json({ error: 'Invalid student code' });
      }
    } else if (targetId) {
      targetUser = await User.findById(targetId);
      if (!targetUser) {
        return res.status(404).json({ error: 'User not found' });
      }
    } else {
      return res.status(400).json({ error: 'Target ID or student code required' });
    }
    
    // Check if already linked
    let teacherId, studentId;
    if (req.role === 'TEACHER') {
      teacherId = req.userId;
      studentId = targetUser._id;
    } else {
      teacherId = targetUser._id;
      studentId = req.userId;
    }
    
    const existingLink = await TeacherStudentLink.findOne({
      teacherId,
      studentId,
      isActive: true
    });
    
    if (existingLink) {
      return res.status(400).json({ error: 'Already linked with this user' });
    }
    
    // Check if blocked
    const blocked = await isBlocked(targetUser._id, req.userId);
    if (blocked) {
      return res.status(403).json({ error: 'Unable to send request to this user' });
    }
    
    // Check existing request
    const existingRequest = await LinkRequest.findOne({
      requesterId: req.userId,
      targetId: targetUser._id,
      status: { $in: ['PENDING', 'BLOCKED'] }
    });
    
    if (existingRequest) {
      if (existingRequest.status === 'PENDING') {
        return res.status(400).json({ error: 'Request already pending' });
      }
      if (existingRequest.status === 'BLOCKED') {
        return res.status(403).json({ error: 'You are blocked from sending requests to this user' });
      }
    }
    
    // Check if target has auto-approve enabled (for teachers)
    let autoApproved = false;
    if (targetUser.role === 'TEACHER') {
      const inviteSettings = await TeacherInviteLink.findOne({ 
        teacherId: targetUser._id,
        autoApprove: true 
      });
      
      if (inviteSettings) {
        // Auto-approve
        const link = await TeacherStudentLink.findOne({ teacherId, studentId });
        if (link) {
          link.isActive = true;
          link.linkedAt = new Date();
          await link.save();
        } else {
          await TeacherStudentLink.create({ teacherId, studentId, isActive: true });
        }
        autoApproved = true;
      }
    }
    
    if (!autoApproved) {
      // Create request
      await LinkRequest.findOneAndUpdate(
        { requesterId: req.userId, targetId: targetUser._id },
        {
          requesterId: req.userId,
          requesterRole: req.role,
          targetId: targetUser._id,
          targetRole: targetUser.role,
          studentCode: studentCode?.toUpperCase(),
          requestMethod: studentCode ? 'STUDENT_CODE' : 'DIRECT',
          status: 'PENDING',
          createdAt: new Date(),
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        },
        { upsert: true, new: true }
      );
    }
    
    // Get requester info for notification
    const requester = await User.findById(req.userId).select('name');
    
    // Send notification
    await createNotification(
      targetUser._id,
      'SYSTEM',
      autoApproved ? 'New Connection' : 'New Link Request',
      autoApproved 
        ? `${requester?.name || 'Someone'} connected with you`
        : `${requester?.name || 'Someone'} wants to connect with you`,
      { 
        requesterId: req.userId, 
        requesterName: requester?.name,
        type: autoApproved ? 'auto_linked' : 'link_request' 
      }
    );
    
    // Real-time notification
    io.to(targetUser._id.toString()).emit(autoApproved ? 'new_link' : 'new_link_request', {
      requesterId: req.userId,
      requesterName: requester?.name,
      autoApproved
    });
    
    res.json({
      success: true,
      autoApproved,
      message: autoApproved 
        ? 'Successfully linked!'
        : 'Request sent! Waiting for approval.',
      target: {
        id: targetUser._id.toString(),
        name: targetUser.name,
        role: targetUser.role
      }
    });
  } catch (error) {
    console.error('Send request error:', error);
    res.status(500).json({ error: 'Failed to send request' });
  }
});

// Cancel sent request
app.delete('/api/requests/:requestId', authRequired, async (req, res) => {
  try {
    const request = await LinkRequest.findOneAndDelete({
      _id: req.params.requestId,
      requesterId: req.userId,
      status: 'PENDING'
    });
    
    if (!request) {
      return res.status(404).json({ error: 'Request not found or cannot be cancelled' });
    }
    
    res.json({
      success: true,
      message: 'Request cancelled'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to cancel request' });
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

// ========= STUDENT CLASSES ENDPOINT - COMPLETE MERGED VERSION =========
// Get all classes for student (both regular and group classes)
// DELETE BOTH OLD ENDPOINTS AND USE ONLY THIS ONE
app.get('/api/student/classes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const studentId = req.userId;
    
    // 1. Get all linked teachers for this student
    const links = await TeacherStudentLink.find({ 
      studentId: studentId, 
      isActive: true,
      isBlocked: { $ne: true }
    }).select('teacherId');
    
    const linkedTeacherIds = links.map(link => link.teacherId);
    
    if (linkedTeacherIds.length === 0) {
      return res.json({ 
        success: true, 
        classes: [],
        message: 'No linked teachers found'
      });
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
    .populate('teacherId', 'name avatar')
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
      status: { $in: ['SCHEDULED', 'LIVE'] },
      $or: [
        { isForAllStudents: true },
        { studentIds: studentId },
        { sectionId: { $in: sectionIds } }
      ]
    })
    .populate('teacherId', 'name avatar')
    .populate('sectionId', 'name')
    .sort({ scheduledAt: 1 })
    .lean();
    
    // ========= FORMAT REGULAR CLASSES =========
    const formattedRegularClasses = regularClasses.map(c => ({
      id: c._id.toString(),
      type: 'REGULAR',
      subject: c.subject || c.title,
      title: c.title || c.subject,
      dayOfWeek: c.dayOfWeek,           // ✅ CRITICAL: 1=Monday to 7=Sunday
      startTime: c.startTime,
      endTime: c.endTime,
      colorHex: c.colorHex || '#3B82F6',
      notes: c.notes,
      location: c.location,
      teacherName: c.teacherId?.name || 'Unknown Teacher',
      teacherAvatar: c.teacherId?.avatar,
      scope: c.scope,
      createdAt: c.createdAt
    }));
    
    // ========= FORMAT GROUP CLASSES =========
    const formattedGroupClasses = groupClasses.map(c => ({
      id: c._id.toString(),
      type: 'GROUP',
      subject: c.subject,
      title: c.title,
      description: c.description,
      scheduledAt: c.scheduledAt?.toISOString(),
      duration: c.duration || 60,
      colorHex: c.colorHex || '#10B981',
      notes: c.notes,
      teacherName: c.teacherId?.name || 'Unknown Teacher',
      teacherAvatar: c.teacherId?.avatar,
      sectionName: c.sectionId?.name,
      status: c.status,
      sessionId: c.sessionId,
      teacherInClass: c.teacherInClass || false,  // ✅ CRITICAL for Join button
      // Settings
      settings: {
        allowStudentVideo: c.allowStudentVideo !== false,
        allowStudentAudio: c.allowStudentAudio !== false,
        allowChat: c.allowChat !== false,
        allowScreenShare: c.allowScreenShare || false,
        allowWhiteboard: c.allowWhiteboard !== false
      },
      // Times
      startedAt: c.startedAt?.toISOString(),
      endedAt: c.endedAt?.toISOString()
    }));
    
    // ========= COMBINE BOTH =========
    const allClasses = [
      ...formattedRegularClasses,
      ...formattedGroupClasses
    ];
    
    // Debug logging
    console.log(`📚 Student ${studentId}: ${formattedRegularClasses.length} regular, ${formattedGroupClasses.length} group classes`);
    if (formattedRegularClasses.length > 0) {
      console.log(`📚 Sample regular: "${formattedRegularClasses[0].subject}" dayOfWeek=${formattedRegularClasses[0].dayOfWeek}`);
    }
    
    res.json({ 
      success: true, 
      classes: allClasses
    });
    
  } catch (error) {
    console.error('Get student classes error:', error);
    res.status(500).json({ error: 'Failed to fetch classes' });
  }
});

// ========= STUDENT GROUP CLASSES - ENHANCED WITH DAY INFO =========
app.get('/api/student/group-classes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    // Get linked teacher IDs
    const links = await TeacherStudentLink.find({ 
      studentId: req.userId, 
      isActive: true,
      isBlocked: false
    }).select('teacherId');
    
    const teacherIds = links.map(link => link.teacherId);
    
    // Find group classes where student is enrolled or class is for all students
    const groupClasses = await GroupClass.find({
      $or: [
        { teacherId: { $in: teacherIds }, isForAllStudents: true },
        { studentIds: req.userId },
        { teacherId: { $in: teacherIds }, sectionId: { $exists: true } }
      ],
      isActive: true,
      status: { $in: ['SCHEDULED', 'LIVE'] } // Only active classes
    })
    .populate('teacherId', 'name avatar')
    .populate('sectionId', 'name')
    .sort({ scheduledAt: 1 })
    .lean();
    
    // Format with dayOfWeek extracted from scheduledAt
    const formattedClasses = groupClasses.map(cls => {
      // Extract day of week from scheduledAt (1=Monday, 7=Sunday)
      const scheduledDate = new Date(cls.scheduledAt);
      let dayOfWeek = scheduledDate.getDay(); // 0=Sunday, 1=Monday, etc.
      // Convert to backend format: 1=Monday, 7=Sunday
      dayOfWeek = dayOfWeek === 0 ? 7 : dayOfWeek;
      
      return {
        id: cls._id.toString(),
        type: 'GROUP',
        title: cls.title,
        subject: cls.subject,
        description: cls.description,
        dayOfWeek: dayOfWeek, // Added for day filtering
        scheduledAt: cls.scheduledAt,
        duration: cls.duration,
        status: cls.status,
        sessionId: cls.sessionId,
        colorHex: cls.colorHex || '#10B981',
        teacherName: cls.teacherId?.name || 'Unknown Teacher',
        teacherAvatar: cls.teacherId?.avatar,
        sectionName: cls.sectionId?.name,
        teacherInClass: cls.teacherInClass || false,
        settings: {
          allowStudentVideo: cls.allowStudentVideo,
          allowStudentAudio: cls.allowStudentAudio,
          allowChat: cls.allowChat,
          allowWhiteboard: cls.allowWhiteboard
        }
      };
    });
    
    console.log(`📺 Student ${req.userId} fetched ${formattedClasses.length} group classes`);
    
    res.json({
      success: true,
      classes: formattedClasses
    });
    
  } catch (error) {
    console.error('Get student group classes error:', error);
    res.status(500).json({ error: 'Failed to fetch group classes' });
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
// ========= POST /api/teacher/classes - Create new class =========
app.post('/api/teacher/classes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { subject, title, dayOfWeek, startTime, endTime, colorHex, notes, location, scope, studentId } = req.body;
    
    // Validate required fields
    if (!subject || !title || !dayOfWeek || !startTime || !endTime) {
      return res.status(400).json({ error: 'Subject, title, dayOfWeek, startTime, and endTime are required' });
    }
    
    // ✅ CRITICAL: Ensure dayOfWeek is a number between 1-7
    const day = parseInt(dayOfWeek, 10);
    if (isNaN(day) || day < 1 || day > 7) {
      return res.status(400).json({ error: 'dayOfWeek must be a number between 1 (Monday) and 7 (Sunday)' });
    }
    
    const newClass = await ClassModel.create({
      teacherId: req.userId,
      subject,
      title,
      dayOfWeek: day,  // ✅ Ensure it's saved as integer
      startTime,
      endTime,
      colorHex: colorHex || '#3B82F6',
      notes,
      location,
      scope: scope || 'ALL',
      studentId: scope === 'INDIVIDUAL' ? studentId : undefined
    });
    
    console.log(`📚 Created class: ${subject} on day ${day} by teacher ${req.userId}`);
    
    res.status(201).json({
      success: true,
      class: {
        id: newClass._id.toString(),
        subject: newClass.subject,
        title: newClass.title,
        dayOfWeek: newClass.dayOfWeek,
        startTime: newClass.startTime,
        endTime: newClass.endTime,
        colorHex: newClass.colorHex
      }
    });
  } catch (error) {
    console.error('Create class error:', error);
    res.status(500).json({ error: 'Failed to create class' });
  }
});

// ========= PUT /api/teacher/classes/:id - Update class =========
app.put('/api/teacher/classes/:id', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { subject, title, dayOfWeek, startTime, endTime, colorHex, notes, location, scope, studentId } = req.body;
    
    const existingClass = await ClassModel.findOne({ _id: req.params.id, teacherId: req.userId });
    if (!existingClass) {
      return res.status(404).json({ error: 'Class not found' });
    }
    
    // ✅ CRITICAL: Update dayOfWeek if provided
    if (dayOfWeek !== undefined) {
      const day = parseInt(dayOfWeek, 10);
      if (isNaN(day) || day < 1 || day > 7) {
        return res.status(400).json({ error: 'dayOfWeek must be between 1 and 7' });
      }
      existingClass.dayOfWeek = day;
    }
    
    if (subject) existingClass.subject = subject;
    if (title) existingClass.title = title;
    if (startTime) existingClass.startTime = startTime;
    if (endTime) existingClass.endTime = endTime;
    if (colorHex) existingClass.colorHex = colorHex;
    if (notes !== undefined) existingClass.notes = notes;
    if (location !== undefined) existingClass.location = location;
    if (scope) existingClass.scope = scope;
    if (scope === 'INDIVIDUAL' && studentId) existingClass.studentId = studentId;
    
    await existingClass.save();
    
    console.log(`📚 Updated class ${req.params.id}: dayOfWeek=${existingClass.dayOfWeek}`);
    
    res.json({
      success: true,
      class: {
        id: existingClass._id.toString(),
        subject: existingClass.subject,
        title: existingClass.title,
        dayOfWeek: existingClass.dayOfWeek,
        startTime: existingClass.startTime,
        endTime: existingClass.endTime
      }
    });
  } catch (error) {
    console.error('Update class error:', error);
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
// 🚀 FIXED: Local-first message deletion WITH socket relay
app.delete('/api/chat/messages/:id', authRequired, async (req, res) => {
  try {
    const messageId = req.params.id;
    const deleteForEveryone = req.query.deleteForEveryone === 'true';
    const conversationId = req.query.conversationId || req.body.conversationId;
    const userId = req.userId;
    
    console.log(`🗑️ Delete request: messageId=${messageId}, conversationId=${conversationId}, deleteForEveryone=${deleteForEveryone}`);
    
    // 🚀 CRITICAL: Emit socket event for real-time sync to OTHER user
    if (deleteForEveryone) {
      const user = await User.findById(userId).select('name');
      
      const deletionData = {
        messageId: messageId,
        conversationId: conversationId || 'unknown',
        deletedBy: userId,
        deletedByName: user?.name || 'Unknown',
        deleteForEveryone: true,
        deletedAt: new Date().toISOString()
      };
      
      // Emit to conversation room (both users will receive)
      if (conversationId && conversationId !== 'unknown') {
        io.to(`conversation_${conversationId}`).emit('message_deleted', deletionData);
        console.log(`📡 Emitted message_deleted to conversation_${conversationId}`);
      }
      
      // Also emit directly to the other user's room (in case they're not in conversation room)
      // Find the conversation to get the other user ID
      try {
        const conversation = await Conversation.findOne({
          $or: [
            { teacherId: userId },
            { studentId: userId }
          ]
        }).select('teacherId studentId');
        
        if (conversation) {
          const otherUserId = conversation.teacherId.toString() === userId 
            ? conversation.studentId.toString() 
            : conversation.teacherId.toString();
          
          io.to(otherUserId).emit('message_deleted', deletionData);
          console.log(`📡 Also emitted message_deleted directly to user ${otherUserId}`);
        }
      } catch (convError) {
        console.log('Could not find conversation for direct emit:', convError.message);
      }
    }
    
    res.json({ 
      success: true, 
      message: deleteForEveryone ? 'Message deleted for everyone' : 'Message deleted for you'
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

// Check if specific user is blocked
// Check if specific user is blocked
app.get('/api/users/block-status/:userId', authRequired, async (req, res) => {
  try {
    const blockerId = req.userId;
    const blockedId = req.params.userId;
    
    const isBlocked = await UserBlock.exists({ 
      blockerId, 
      blockedId 
    });
    
    res.json({ 
      success: true, 
      isBlocked: !!isBlocked 
    });
  } catch (error) {
    console.error('Check block status error:', error);
    res.status(500).json({ error: 'Failed to check block status' });
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
// Get teacher group classes - optionally filter out old ENDED classes
app.get('/api/teacher/group-classes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { includeEnded } = req.query;
    
    const query = { teacherId: req.userId };
    
    // By default, hide classes that ended more than 1 hour ago
    if (!includeEnded) {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      query.$or = [
        { status: { $ne: 'ENDED' } },
        { status: 'ENDED', endedAt: { $gte: oneHourAgo } }
      ];
    }
    
    const groupClasses = await GroupClass.find(query)
      .populate('sectionId', 'name')
      .sort({ scheduledAt: -1 })
      .lean();
    
    const formatted = groupClasses.map(gc => ({
      id: gc._id.toString(),
      title: gc.title,
      subject: gc.subject,
      description: gc.description,
      scheduledAt: gc.scheduledAt,
      duration: gc.duration,
      status: gc.status,
      sessionId: gc.sessionId,
      sectionName: gc.sectionId?.name,
      studentCount: gc.isForAllStudents ? 'All Students' : (gc.studentIds?.length || 0),
      teacherInClass: gc.teacherInClass || false,
      settings: {
        allowStudentVideo: gc.allowStudentVideo,
        allowStudentAudio: gc.allowStudentAudio,
        allowChat: gc.allowChat,
        allowScreenShare: gc.allowScreenShare,
        muteOnJoin: gc.muteOnJoin
      },
      colorHex: gc.colorHex,
      createdAt: gc.createdAt
    }));
    
    res.json({ success: true, classes: formatted });
  } catch (error) {
    console.error('Get teacher group classes error:', error);
    res.status(500).json({ error: 'Failed to fetch group classes' });
  }
});

// Get student's group classes - UPDATED
app.get('/api/student/group-classes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    // Get all classes where student is enrolled
    const links = await TeacherStudentLink.find({ 
      studentId: req.userId, 
      isActive: true 
    });
    const teacherIds = links.map(l => l.teacherId);

    const classes = await GroupClass.find({
      teacherId: { $in: teacherIds },
      isActive: true,
      $or: [
        { isForAllStudents: true },
        { studentIds: req.userId }
      ],
      status: { $in: ['SCHEDULED', 'LIVE'] }
    })
    .populate('teacherId', 'name avatar')
    .sort({ scheduledAt: 1 })
    .lean();

    const now = new Date();

    res.json({
      success: true,
      classes: classes.map(c => {
        const scheduledTime = new Date(c.scheduledAt);
        const joinWindowMs = (c.joinWindowMinutes || 10) * 60 * 1000;
        const canJoinAt = new Date(scheduledTime.getTime() - joinWindowMs);
        const canJoin = now >= canJoinAt;
        
        // Check if student is in waiting room
        const inWaitingRoom = c.waitingRoom?.some(
          w => w.userId?.toString() === req.userId
        );

        return {
  id: c._id.toString(),
  title: c.title,
  subject: c.subject,
  description: c.description,
  scheduledAt: c.scheduledAt,
  duration: c.duration,
  teacherName: c.teacherId?.name,
  teacherAvatar: c.teacherId?.avatar,
  status: c.status,
  sessionId: c.sessionId,
  teacherInClass: c.teacherInClass || false,  // ← ADD THIS LINE
  settings: {
    allowStudentVideo: c.allowStudentVideo,
    allowStudentAudio: c.allowStudentAudio,
    allowChat: c.allowChat,
    allowScreenShare: c.allowScreenShare,
    muteOnJoin: c.muteOnJoin
  },
  colorHex: c.colorHex,
  canJoin: c.status === 'LIVE' && c.teacherInClass === true,  // ← CHANGE THIS LINE
  canJoinAt: canJoinAt.toISOString(),
  inWaitingRoom: inWaitingRoom,
  createdAt: c.createdAt
};
      })
    });
  } catch (error) {
    console.error('Get student group classes error:', error);
    res.status(500).json({ error: 'Failed to fetch group classes' });
  }
});

// Create group class
// Create Group Class - UPDATED with sessionId generation
app.post('/api/teacher/group-classes', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const {
      title, subject, description, scheduledAt, duration,
      sectionId, studentIds, isForAllStudents,
      allowStudentVideo, allowStudentAudio, allowChat,
      allowScreenShare, allowWhiteboard, muteOnJoin,
      colorHex, notes
    } = req.body;

    if (!title || !subject || !scheduledAt) {
      return res.status(400).json({ error: 'Title, subject, and scheduled time are required' });
    }

    // Generate unique session ID for Jitsi
    const sessionId = `tm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Determine which students to include
    let finalStudentIds = [];
    
    if (isForAllStudents) {
      const links = await TeacherStudentLink.find({ teacherId: req.userId, isActive: true });
      finalStudentIds = links.map(l => l.studentId);
    } else if (sectionId) {
      const section = await Section.findById(sectionId);
      if (section) {
        finalStudentIds = section.studentIds || [];
      }
    } else if (studentIds && studentIds.length > 0) {
      finalStudentIds = studentIds;
    }

    const groupClass = await GroupClass.create({
      teacherId: req.userId,
      title,
      subject,
      description,
      scheduledAt: new Date(scheduledAt),
      duration: duration || 60,
      sectionId,
      studentIds: finalStudentIds,
      isForAllStudents: isForAllStudents || false,
      allowStudentVideo: allowStudentVideo !== false,
      allowStudentAudio: allowStudentAudio !== false,
      allowChat: allowChat !== false,
      allowScreenShare: allowScreenShare || false,
      allowWhiteboard: allowWhiteboard !== false,
      muteOnJoin: muteOnJoin || false,
      colorHex: colorHex || '#10B981',
      notes,
      sessionId,
      joinWindowMinutes: 10 // Students can join 10 minutes before
    });

    // Notify enrolled students about the scheduled class
    for (const studentId of finalStudentIds) {
      await createNotification(
        studentId,
        'CLASS',
        'New Group Class Scheduled',
        `${title} is scheduled for ${new Date(scheduledAt).toLocaleString()}`,
        { classId: groupClass._id.toString(), type: 'group_class_scheduled' }
      );
      
      io.to(studentId.toString()).emit('group-class-scheduled', {
        classId: groupClass._id.toString(),
        title,
        scheduledAt,
        teacherId: req.userId
      });
    }

    console.log(`📚 Group class created: ${title} with sessionId: ${sessionId}`);

    res.status(201).json({
      success: true,
      classId: groupClass._id.toString(),
      sessionId: groupClass.sessionId
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
// Teacher starts group class - UPDATED with waiting room notification
app.post('/api/teacher/group-classes/:id/start', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const groupClass = await GroupClass.findOne({ 
      _id: req.params.id, 
      teacherId: req.userId 
    });
    
    if (!groupClass) {
      return res.status(404).json({ error: 'Class not found' });
    }

    if (groupClass.status === 'LIVE') {
      return res.json({ 
        success: true, 
        sessionId: groupClass.sessionId,
        message: 'Class is already live'
      });
    }

    if (groupClass.status === 'ENDED') {
      return res.status(400).json({ error: 'Class has already ended' });
    }

    // Generate sessionId if not exists
    if (!groupClass.sessionId) {
      groupClass.sessionId = `tm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    groupClass.status = 'LIVE';
    groupClass.startedAt = new Date();
    await groupClass.save();

    // Get all enrolled students
    let studentIds = groupClass.studentIds || [];
    if (groupClass.isForAllStudents) {
      const links = await TeacherStudentLink.find({ teacherId: req.userId, isActive: true });
      studentIds = links.map(l => l.studentId);
    }

    // Notify ALL enrolled students that class has started
    for (const studentId of studentIds) {
      io.to(studentId.toString()).emit('group-class-started', {
        classId: groupClass._id.toString(),
        sessionId: groupClass.sessionId,
        title: groupClass.title,
        settings: {
          allowStudentVideo: groupClass.allowStudentVideo,
          allowStudentAudio: groupClass.allowStudentAudio,
          allowChat: groupClass.allowChat,
          allowScreenShare: groupClass.allowScreenShare,
          muteOnJoin: groupClass.muteOnJoin
        }
      });
    }

    // Notify students in waiting room specifically (they should auto-redirect)
    io.to(`waiting-${groupClass._id.toString()}`).emit('class-started-join-now', {
      classId: groupClass._id.toString(),
      sessionId: groupClass.sessionId,
      title: groupClass.title,
      settings: {
        allowStudentVideo: groupClass.allowStudentVideo,
        allowStudentAudio: groupClass.allowStudentAudio,
        allowChat: groupClass.allowChat,
        allowScreenShare: groupClass.allowScreenShare,
        muteOnJoin: groupClass.muteOnJoin
      }
    });

    // Clear waiting room
    groupClass.waitingRoom = [];
    await groupClass.save();

    console.log(`🎥 Group class started: ${groupClass.title} (${groupClass.sessionId})`);

    res.json({
      success: true,
      sessionId: groupClass.sessionId,
      message: 'Class started'
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

// Student joins waiting room (before teacher starts)
app.post('/api/student/group-classes/:id/join-waiting', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    const groupClass = await GroupClass.findById(req.params.id);
    
    if (!groupClass) {
      return res.status(404).json({ error: 'Class not found' });
    }

    // Check if student is enrolled
    const isEnrolled = groupClass.isForAllStudents || 
      groupClass.studentIds.some(id => id.toString() === req.userId);
    
    if (!isEnrolled) {
      return res.status(403).json({ error: 'You are not enrolled in this class' });
    }

    // Check if within join window
    const now = new Date();
    const scheduledTime = new Date(groupClass.scheduledAt);
    const joinWindowMs = (groupClass.joinWindowMinutes || 10) * 60 * 1000;
    const canJoinAt = new Date(scheduledTime.getTime() - joinWindowMs);
    
    if (now < canJoinAt) {
      const minutesUntilJoin = Math.ceil((canJoinAt - now) / 60000);
      return res.status(400).json({ 
        error: 'Too early to join',
        canJoinAt: canJoinAt.toISOString(),
        minutesUntilJoin
      });
    }

    // If class is already LIVE, redirect to join directly
    if (groupClass.status === 'LIVE') {
      return res.json({
        success: true,
        status: 'LIVE',
        sessionId: groupClass.sessionId,
        message: 'Class is live, join now'
      });
    }

    // If class has ended
    if (groupClass.status === 'ENDED' || groupClass.status === 'CANCELLED') {
      return res.status(400).json({ error: 'Class has ended or was cancelled' });
    }

    // Add to waiting room if not already there
    const alreadyInWaiting = groupClass.waitingRoom?.some(
      w => w.userId?.toString() === req.userId
    );
    
    if (!alreadyInWaiting) {
      if (!groupClass.waitingRoom) {
        groupClass.waitingRoom = [];
      }
      groupClass.waitingRoom.push({
        userId: req.userId,
        joinedAt: new Date()
      });
      await groupClass.save();
    }

    // Join socket room for waiting room updates
    const socketId = connectedUsers.get(req.userId);
    if (socketId) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.join(`waiting-${groupClass._id.toString()}`);
      }
    }

    console.log(`⏳ Student ${req.userId} joined waiting room for class ${groupClass._id}`);

    res.json({
      success: true,
      status: 'WAITING',
      message: 'You are in the waiting room. You will be notified when the teacher starts the class.',
      classTitle: groupClass.title,
      scheduledAt: groupClass.scheduledAt,
      teacherId: groupClass.teacherId
    });
  } catch (error) {
    console.error('Join waiting room error:', error);
    res.status(500).json({ error: 'Failed to join waiting room' });
  }
});

// Student leaves waiting room
app.post('/api/student/group-classes/:id/leave-waiting', authRequired, async (req, res) => {
  try {
    await GroupClass.findByIdAndUpdate(req.params.id, {
      $pull: { waitingRoom: { userId: req.userId } }
    });

    // Leave socket room
    const socketId = connectedUsers.get(req.userId);
    if (socketId) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.leave(`waiting-${req.params.id}`);
      }
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to leave waiting room' });
  }
});

// Check class status (for polling or on resume)
app.get('/api/group-classes/:id/status', authRequired, async (req, res) => {
  try {
    const groupClass = await GroupClass.findById(req.params.id)
      .select('status sessionId scheduledAt title teacherId settings')
      .lean();
    
    if (!groupClass) {
      return res.status(404).json({ error: 'Class not found' });
    }

    // Calculate if join is allowed
    const now = new Date();
    const scheduledTime = new Date(groupClass.scheduledAt);
    const joinWindowMs = 10 * 60 * 1000; // 10 minutes
    const canJoinAt = new Date(scheduledTime.getTime() - joinWindowMs);
    const canJoin = now >= canJoinAt;

    res.json({
      success: true,
      status: groupClass.status,
      sessionId: groupClass.sessionId,
      canJoin,
      canJoinAt: canJoinAt.toISOString(),
      scheduledAt: groupClass.scheduledAt,
      settings: {
        allowStudentVideo: groupClass.allowStudentVideo,
        allowStudentAudio: groupClass.allowStudentAudio,
        allowChat: groupClass.allowChat,
        allowScreenShare: groupClass.allowScreenShare,
        muteOnJoin: groupClass.muteOnJoin
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get class status' });
  }
});

// Get student group classes - filter out ENDED classes
app.get('/api/student/group-classes', authRequired, requireRole('STUDENT'), async (req, res) => {
  try {
    // Get all teachers linked to this student
    const links = await TeacherStudentLink.find({ 
      studentId: req.userId, 
      isActive: true 
    }).select('teacherId');
    
    const teacherIds = links.map(l => l.teacherId);
    
    // Find group classes from linked teachers that are NOT ENDED
    const groupClasses = await GroupClass.find({
      teacherId: { $in: teacherIds },
      status: { $ne: 'ENDED' }, // Exclude ended classes
      isActive: true,
      $or: [
        { isForAllStudents: true },
        { studentIds: req.userId }
      ]
    })
    .populate('teacherId', 'name avatar')
    .populate('sectionId', 'name')
    .sort({ scheduledAt: 1 })
    .lean();
    
    const formatted = groupClasses.map(gc => ({
      id: gc._id.toString(),
      title: gc.title,
      subject: gc.subject,
      description: gc.description,
      scheduledAt: gc.scheduledAt,
      duration: gc.duration,
      status: gc.status,
      sessionId: gc.sessionId,
      teacherName: gc.teacherId?.name,
      teacherAvatar: gc.teacherId?.avatar,
      sectionName: gc.sectionId?.name,
      studentCount: gc.isForAllStudents ? 'All Students' : (gc.studentIds?.length || 0),
      teacherInClass: gc.teacherInClass || false, // CRITICAL: Include this!
      canJoin: gc.status === 'LIVE' && gc.teacherInClass === true, // Only allow join if teacher is in class
      settings: {
        allowStudentVideo: gc.allowStudentVideo,
        allowStudentAudio: gc.allowStudentAudio,
        allowChat: gc.allowChat,
        allowScreenShare: gc.allowScreenShare,
        muteOnJoin: gc.muteOnJoin
      },
      colorHex: gc.colorHex,
      createdAt: gc.createdAt
    }));
    
    res.json({ success: true, classes: formatted });
  } catch (error) {
    console.error('Get student group classes error:', error);
    res.status(500).json({ error: 'Failed to fetch group classes' });
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



// ========= ADMIN PANEL API ENDPOINTS =========

// Rate limiting for admin routes (stricter)
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Too many admin requests' },
  trustProxy: 1
});
app.use('/api/admin/', adminLimiter);

// ========= ADMIN AUTH =========

// Admin Login
// Admin Login (WITH 2FA SUPPORT)
app.post('/api/admin/auth/login', async (req, res) => {
  try {
    const { email, password, deviceInfo } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    const admin = await AdminUser.findOne({ email: email.toLowerCase() });
    
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check if locked
    if (admin.lockedUntil && new Date() < admin.lockedUntil) {
      const remainingMinutes = Math.ceil((admin.lockedUntil - new Date()) / 60000);
      return res.status(423).json({ 
        error: `Account locked. Try again in ${remainingMinutes} minutes.` 
      });
    }
    
    // Verify password
    const isValid = await bcrypt.compare(password, admin.passwordHash);
    
    if (!isValid) {
      admin.failedLoginAttempts += 1;
      if (admin.failedLoginAttempts >= 5) {
        admin.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        admin.failedLoginAttempts = 0;
      }
      await admin.save();
      
      await logAdminAction(admin._id, admin.email, 'LOGIN_FAILED', 'AUTH', null, 
        { reason: 'Invalid password', attempts: admin.failedLoginAttempts }, 
        req, 'FAILED'
      );
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check if 2FA is enabled
    if (admin.twoFactorEnabled) {
      // Generate temporary token for 2FA verification
      const twoFactorToken = jwt.sign(
        { sub: admin._id, email: admin.email, purpose: '2fa' },
        ADMIN_JWT_SECRET,
        { expiresIn: '5m' } // 5 minutes to complete 2FA
      );
      
      return res.json({
        success: true,
        requiresTwoFactor: true,
        twoFactorToken: twoFactorToken,
        message: 'Please enter your 2FA code'
      });
    }
    
    // Reset failed attempts and complete login
    admin.failedLoginAttempts = 0;
    admin.lockedUntil = null;
    admin.lastLogin = new Date();
    admin.lastLoginIP = req.ip || req.connection.remoteAddress;
    await admin.save();
    
    // Generate tokens
    const accessToken = jwt.sign(
      { sub: admin._id, email: admin.email, role: admin.role },
      ADMIN_JWT_SECRET,
      { expiresIn: ADMIN_TOKEN_EXPIRY }
    );
    
    const refreshToken = generateSecureToken();
    
    // Create session
    await AdminSession.create({
      adminId: admin._id,
      token: accessToken,
      refreshToken,
      deviceInfo: deviceInfo || 'Unknown',
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000)
    });
    
    await logAdminAction(admin._id, admin.email, 'LOGIN_SUCCESS', 'AUTH', null, 
      { deviceInfo }, req
    );
    
    res.json({
      success: true,
      accessToken,
      refreshToken,
      expiresIn: 8 * 60 * 60,
      admin: {
        id: admin._id.toString(),
        email: admin.email,
        name: admin.name,
        role: admin.role,
        permissions: admin.permissions,
        avatar: admin.avatar
      }
    });
    
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Verify 2FA during login
app.post('/api/admin/auth/verify-2fa', async (req, res) => {
  try {
    const { twoFactorToken, code, isBackupCode } = req.body;
    
    if (!twoFactorToken || !code) {
      return res.status(400).json({ error: 'Token and code are required' });
    }
    
    // Verify the temporary token
    let decoded;
    try {
      decoded = jwt.verify(twoFactorToken, ADMIN_JWT_SECRET);
      if (decoded.purpose !== '2fa') {
        return res.status(401).json({ error: 'Invalid token' });
      }
    } catch (err) {
      return res.status(401).json({ error: 'Token expired. Please login again.' });
    }
    
    const admin = await AdminUser.findById(decoded.sub);
    if (!admin || !admin.twoFactorEnabled) {
      return res.status(401).json({ error: 'Invalid request' });
    }
    
    let verified = false;
    
    if (isBackupCode) {
      // Check backup codes
      const backupCode = admin.twoFactorBackupCodes.find(bc => bc.code === code && !bc.used);
      if (backupCode) {
        verified = true;
        backupCode.used = true;
        await admin.save();
      }
    } else {
      // Verify TOTP code
      verified = speakeasy.totp.verify({
        secret: admin.twoFactorSecret,
        encoding: 'base32',
        token: code,
        window: 2
      });
    }
    
    if (!verified) {
      await logAdminAction(admin._id, admin.email, '2FA_FAILED', 'AUTH', null, 
        { isBackupCode }, req, 'FAILED'
      );
      return res.status(401).json({ error: 'Invalid code' });
    }
    
    // Complete login
    admin.failedLoginAttempts = 0;
    admin.lockedUntil = null;
    admin.lastLogin = new Date();
    admin.lastLoginIP = req.ip || req.connection.remoteAddress;
    await admin.save();
    
    // Generate tokens
    const accessToken = jwt.sign(
      { sub: admin._id, email: admin.email, role: admin.role },
      ADMIN_JWT_SECRET,
      { expiresIn: ADMIN_TOKEN_EXPIRY }
    );
    
    const refreshToken = generateSecureToken();
    
    // Create session
    await AdminSession.create({
      adminId: admin._id,
      token: accessToken,
      refreshToken,
      deviceInfo: req.body.deviceInfo || 'Unknown',
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000)
    });
    
    await logAdminAction(admin._id, admin.email, 'LOGIN_SUCCESS_2FA', 'AUTH', null, 
      { isBackupCode }, req
    );
    
    res.json({
      success: true,
      accessToken,
      refreshToken,
      expiresIn: 8 * 60 * 60,
      admin: {
        id: admin._id.toString(),
        email: admin.email,
        name: admin.name,
        role: admin.role,
        permissions: admin.permissions,
        avatar: admin.avatar
      }
    });
    
  } catch (error) {
    console.error('2FA verify login error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Refresh Token
app.post('/api/admin/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }
    
    const session = await AdminSession.findOne({ refreshToken, isActive: true });
    if (!session) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    
    const admin = await AdminUser.findById(session.adminId);
    if (!admin || !admin.isActive) {
      return res.status(401).json({ error: 'Account deactivated' });
    }
    
    // Generate new tokens
    const newAccessToken = jwt.sign(
      { sub: admin._id, email: admin.email, role: admin.role },
      ADMIN_JWT_SECRET,
      { expiresIn: ADMIN_TOKEN_EXPIRY }
    );
    
    const newRefreshToken = generateSecureToken();
    
    // Update session
    session.token = newAccessToken;
    session.refreshToken = newRefreshToken;
    session.expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);
    await session.save();
    
    res.json({
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: 8 * 60 * 60
    });
    
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// Logout
app.post('/api/admin/auth/logout', adminAuthRequired, async (req, res) => {
  try {
    await AdminSession.findByIdAndUpdate(req.sessionId, { isActive: false });
    await logAdminAction(req.adminId, req.adminEmail, 'LOGOUT', 'AUTH', null, {}, req);
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Logout All Sessions
app.post('/api/admin/auth/logout-all', adminAuthRequired, async (req, res) => {
  try {
    await AdminSession.updateMany({ adminId: req.adminId }, { isActive: false });
    await logAdminAction(req.adminId, req.adminEmail, 'LOGOUT_ALL_SESSIONS', 'AUTH', null, {}, req);
    res.json({ success: true, message: 'All sessions terminated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to logout all sessions' });
  }
});

// ========= ADD THIS - Logout from all sessions =========
app.post('/api/admin/logout-all', adminAuthRequired, async (req, res) => {
  try {
    // Delete all sessions for this admin
    const deletedCount = await AdminSession.deleteMany({ adminId: req.adminId });
    
    await logAdminAction(req.adminId, req.adminEmail, 'LOGOUT_ALL_SESSIONS', 'AUTH', null, 
      { sessionsTerminated: deletedCount.deletedCount }, req
    );
    
    res.json({ 
      success: true, 
      message: 'All sessions terminated',
      sessionsTerminated: deletedCount.deletedCount
    });
  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({ error: 'Failed to logout all sessions' });
  }
});

// Get Current Admin
app.get('/api/admin/auth/me', adminAuthRequired, async (req, res) => {
  try {
    const admin = await AdminUser.findById(req.adminId)
      .select('-passwordHash -twoFactorSecret');
    
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    res.json({
      success: true,
      admin: {
        id: admin._id.toString(),
        email: admin.email,
        name: admin.name,
        role: admin.role,
        permissions: admin.permissions,
        avatar: admin.avatar,
        twoFactorEnabled: admin.twoFactorEnabled,
        lastLogin: admin.lastLogin,
        createdAt: admin.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch admin profile' });
  }
});

// Change Password
app.post('/api/admin/auth/change-password', adminAuthRequired, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Both passwords required' });
    }
    
    if (newPassword.length < 12) {
      return res.status(400).json({ error: 'Password must be at least 12 characters' });
    }
    
    const admin = await AdminUser.findById(req.adminId);
    const isValid = await bcrypt.compare(currentPassword, admin.passwordHash);
    
    if (!isValid) {
      await logAdminAction(req.adminId, req.adminEmail, 'PASSWORD_CHANGE_FAILED', 'AUTH', null, 
        { reason: 'Invalid current password' }, req, 'FAILED'
      );
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    admin.passwordHash = await bcrypt.hash(newPassword, 12);
    admin.passwordChangedAt = new Date();
    await admin.save();
    
    // Invalidate all other sessions
    await AdminSession.updateMany(
      { adminId: req.adminId, _id: { $ne: req.sessionId } },
      { isActive: false }
    );
    
    await logAdminAction(req.adminId, req.adminEmail, 'PASSWORD_CHANGED', 'AUTH', null, {}, req);
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// ========= DASHBOARD =========

// ========================================
// ========= DASHBOARD APIs =========
// ========================================

// Dashboard Stats
app.get('/api/admin/dashboard/stats', adminAuthRequired, requireAdminPermission('VIEW_DASHBOARD'), async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    
    const [
      totalUsers,
      activeUsers,
      totalTeachers,
      totalStudents,
      newUsersThisMonth,
      newUsersThisWeek,
      onlineUsers,
      totalMessages,
      totalAssignments,
      totalClasses,
      totalExams,
      totalSubscriptions,
      activeSubscriptions,
      totalRevenue
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isActive: true }),
      User.countDocuments({ role: 'TEACHER', isActive: true }),
      User.countDocuments({ role: 'STUDENT', isActive: true }),
      User.countDocuments({ createdAt: { $gte: thirtyDaysAgo } }),
      User.countDocuments({ createdAt: { $gte: sevenDaysAgo } }),
      User.countDocuments({ isOnline: true }),
      Message.countDocuments(),
      Assignment.countDocuments(),
      ClassModel.countDocuments(),
      Exam.countDocuments(),
      UserSubscription.countDocuments(),
      UserSubscription.countDocuments({ status: 'active' }),
      Transaction.aggregate([
        { $match: { type: 'subscription', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ])
    ]);

    // Calculate growth percentages
    const prevMonthUsers = await User.countDocuments({ 
      createdAt: { $gte: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000), $lt: thirtyDaysAgo } 
    });
    const userGrowth = prevMonthUsers > 0 ? ((newUsersThisMonth - prevMonthUsers) / prevMonthUsers * 100).toFixed(1) : 0;

    res.json({
      success: true,
      stats: {
        users: {
          total: totalUsers,
          active: activeUsers,
          teachers: totalTeachers,
          students: totalStudents,
          online: onlineUsers,
          newThisMonth: newUsersThisMonth,
          newThisWeek: newUsersThisWeek,
          growthPercentage: parseFloat(userGrowth)
        },
        content: {
          messages: totalMessages,
          assignments: totalAssignments,
          classes: totalClasses,
          exams: totalExams
        },
        subscriptions: {
          total: totalSubscriptions,
          active: activeSubscriptions,
          revenue: totalRevenue[0]?.total || 0
        },
        system: {
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          nodeVersion: process.version
        }
      }
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// User Growth Data
// ========= ADD THIS - User Growth Data =========
app.get('/api/admin/dashboard/user-growth', adminAuthRequired, requireAdminPermission('VIEW_DASHBOARD'), async (req, res) => {
  try {
    const { period = '30' } = req.query; // days
    const daysAgo = parseInt(period);
    const startDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
    
    // Get daily user registrations
    const growth = await User.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            day: { $dayOfMonth: '$createdAt' }
          },
          teachers: { $sum: { $cond: [{ $eq: ['$role', 'TEACHER'] }, 1, 0] } },
          students: { $sum: { $cond: [{ $eq: ['$role', 'STUDENT'] }, 1, 0] } },
          total: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } }
    ]);
    
    const formatted = growth.map(g => ({
      date: `${g._id.year}-${String(g._id.month).padStart(2, '0')}-${String(g._id.day).padStart(2, '0')}`,
      teachers: g.teachers,
      students: g.students,
      total: g.total
    }));
    
    res.json({ 
      success: true, 
      growth: formatted, 
      period: daysAgo 
    });
  } catch (error) {
    console.error('User growth error:', error);
    res.status(500).json({ error: 'Failed to fetch growth data' });
  }
});

// ========================================
// ========= SERVER MONITORING APIs =========
// ========================================

// Server Stats
app.get('/api/admin/server/stats', adminAuthRequired, requireAdminPermission('VIEW_SERVER_STATS'), async (req, res) => {
  try {
    const os = require('os');
    
    const stats = {
      uptime: process.uptime(),
      serverTime: new Date().toISOString(),
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem(),
        usagePercentage: ((os.totalmem() - os.freemem()) / os.totalmem() * 100).toFixed(2)
      },
      cpu: {
        model: os.cpus()[0].model,
        cores: os.cpus().length,
        usage: os.loadavg()
      },
      process: {
        memory: process.memoryUsage(),
        pid: process.pid,
        nodeVersion: process.version,
        platform: process.platform
      },
      connections: {
        socketConnections: connectedUsers.size,
        activeCalls: activeCalls.size
      }
    };
    
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch server stats' });
  }
});

// Database Stats
app.get('/api/admin/server/database', adminAuthRequired, requireAdminPermission('VIEW_SERVER_STATS'), async (req, res) => {
  try {
    const dbStats = await mongoose.connection.db.stats();
    const collections = await mongoose.connection.db.listCollections().toArray();
    
    const collectionStats = await Promise.all(
      collections.map(async (col) => {
        const stats = await mongoose.connection.db.collection(col.name).stats();
        return {
          name: col.name,
          documents: stats.count,
          size: stats.size,
          avgDocSize: stats.avgObjSize,
          indexes: stats.nindexes
        };
      })
    );
    
    res.json({
      success: true,
      database: {
        name: mongoose.connection.name,
        collections: dbStats.collections,
        dataSize: dbStats.dataSize,
        storageSize: dbStats.storageSize,
        indexes: dbStats.indexes,
        indexSize: dbStats.indexSize,
        collections: collectionStats.sort((a, b) => b.documents - a.documents)
      }
    });
  } catch (error) {
    console.error('Database stats error:', error);
    res.status(500).json({ error: 'Failed to fetch database stats' });
  }
});

// Socket Stats
app.get('/api/admin/server/sockets', adminAuthRequired, requireAdminPermission('VIEW_SERVER_STATS'), async (req, res) => {
  try {
    const sockets = Array.from(connectedUsers.entries()).map(([userId, socketId]) => ({
      userId,
      socketId,
      connected: true
    }));
    
    res.json({
      success: true,
      sockets: {
        total: connectedUsers.size,
        connections: sockets,
        activeCalls: activeCalls.size
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch socket stats' });
  }
});

// Server Logs (last 100 entries)
app.get('/api/admin/server/logs', adminAuthRequired, requireAdminPermission('VIEW_LOGS'), async (req, res) => {
  try {
    const { limit = 100, level } = req.query;
    
    // In production, read from actual log files or logging service
    const recentLogs = await AdminAuditLog.find(level ? { action: { $regex: level, $options: 'i' } } : {})
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .lean();
    
    res.json({
      success: true,
      logs: recentLogs.map(log => ({
        timestamp: log.createdAt,
        level: log.status === 'SUCCESS' ? 'info' : 'error',
        message: `${log.action} - ${log.resource}`,
        details: log.details
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// ========================================
// ========= REAL-TIME ANALYTICS APIs =========
// ========================================

// Live Users
app.get('/api/admin/analytics/live-users', adminAuthRequired, requireAdminPermission('VIEW_ANALYTICS'), async (req, res) => {
  try {
    const onlineUsers = await User.find({ isOnline: true })
      .select('name email role lastSeen')
      .sort({ lastSeen: -1 })
      .limit(100)
      .lean();
    
    res.json({
      success: true,
      count: onlineUsers.length,
      users: onlineUsers.map(u => ({
        id: u._id.toString(),
        name: u.name,
        email: u.email,
        role: u.role,
        lastSeen: u.lastSeen
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch live users' });
  }
});

// Activity Feed
app.get('/api/admin/analytics/activity-feed', adminAuthRequired, requireAdminPermission('VIEW_ANALYTICS'), async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    
    const [recentMessages, recentAssignments, recentLogins] = await Promise.all([
      Message.find({ createdAt: { $gte: fiveMinutesAgo } })
        .populate('senderId', 'name role')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Assignment.find({ createdAt: { $gte: fiveMinutesAgo } })
        .populate('teacherId', 'name')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      User.find({ lastLogin: { $gte: fiveMinutesAgo } })
        .select('name role lastLogin')
        .sort({ lastLogin: -1 })
        .limit(20)
        .lean()
    ]);
    
    const activities = [
      ...recentMessages.map(m => ({
        type: 'message',
        user: m.senderId?.name,
        action: 'sent a message',
        timestamp: m.createdAt
      })),
      ...recentAssignments.map(a => ({
        type: 'assignment',
        user: a.teacherId?.name,
        action: 'created assignment',
        timestamp: a.createdAt
      })),
      ...recentLogins.map(u => ({
        type: 'login',
        user: u.name,
        action: 'logged in',
        timestamp: u.lastLogin
      }))
    ].sort((a, b) => b.timestamp - a.timestamp).slice(0, parseInt(limit));
    
    res.json({ success: true, activities });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch activity feed' });
  }
});

// Performance Metrics
app.get('/api/admin/analytics/performance', adminAuthRequired, requireAdminPermission('VIEW_ANALYTICS'), async (req, res) => {
  try {
    res.json({
      success: true,
      performance: {
        avgResponseTime: 150, // Implement actual metrics
        requestsPerMinute: 45,
        errorRate: 0.5,
        activeConnections: connectedUsers.size,
        dbQueryTime: 25
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch performance metrics' });
  }
});

// Error Logs
app.get('/api/admin/analytics/errors', adminAuthRequired, requireAdminPermission('VIEW_ANALYTICS'), async (req, res) => {
  try {
    const errors = await AdminAuditLog.find({ status: 'FAILED' })
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();
    
    res.json({
      success: true,
      errors: errors.map(e => ({
        timestamp: e.createdAt,
        action: e.action,
        admin: e.adminEmail,
        details: e.details
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch error logs' });
  }
});

// ========================================
// ========= CONTENT MANAGEMENT APIs =========
// ========================================

// Get All Classes
app.get('/api/admin/content/classes', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [classes, total] = await Promise.all([
      ClassModel.find()
        .populate('teacherId', 'name email')
        .populate('studentId', 'name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      ClassModel.countDocuments()
    ]);
    
    res.json({
      success: true,
      classes: classes.map(c => ({
        id: c._id.toString(),
        teacher: c.teacherId?.name,
        teacherEmail: c.teacherId?.email,
        subject: c.subject,
        title: c.title,
        dayOfWeek: c.dayOfWeek,
        startTime: c.startTime,
        endTime: c.endTime,
        scope: c.scope,
        isActive: c.isActive,
        createdAt: c.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch classes' });
  }
});

// Get All Assignments
app.get('/api/admin/content/assignments', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [assignments, total] = await Promise.all([
      Assignment.find()
        .populate('teacherId', 'name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Assignment.countDocuments()
    ]);
    
    res.json({
      success: true,
      assignments: assignments.map(a => ({
        id: a._id.toString(),
        teacher: a.teacherId?.name,
        title: a.title,
        description: a.description,
        dueAt: a.dueAt,
        status: a.status,
        priority: a.priority,
        submissionCount: a.submissionCount,
        createdAt: a.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch assignments' });
  }
});

// Get All Exams
app.get('/api/admin/content/exams', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [exams, total] = await Promise.all([
      Exam.find()
        .populate('teacherId', 'name email')
        .sort({ whenAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Exam.countDocuments()
    ]);
    
    res.json({
      success: true,
      exams: exams.map(e => ({
        id: e._id.toString(),
        teacher: e.teacherId?.name,
        title: e.title,
        description: e.description,
        whenAt: e.whenAt,
        maxMarks: e.maxMarks,
        duration: e.duration,
        isActive: e.isActive,
        createdAt: e.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch exams' });
  }
});

// Get All Notes
app.get('/api/admin/content/notes', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [notes, total] = await Promise.all([
      Note.find()
        .populate('teacherId', 'name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Note.countDocuments()
    ]);
    
    res.json({
      success: true,
      notes: notes.map(n => ({
        id: n._id.toString(),
        teacher: n.teacherId?.name,
        title: n.title,
        subject: n.subject,
        category: n.category,
        isPinned: n.isPinned,
        createdAt: n.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notes' });
  }
});

// Get All Group Classes
app.get('/api/admin/content/group-classes', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [groupClasses, total] = await Promise.all([
      GroupClass.find()
        .populate('teacherId', 'name email')
        .sort({ scheduledAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      GroupClass.countDocuments()
    ]);
    
    res.json({
      success: true,
      groupClasses: groupClasses.map(gc => ({
        id: gc._id.toString(),
        teacher: gc.teacherId?.name,
        title: gc.title,
        subject: gc.subject,
        scheduledAt: gc.scheduledAt,
        duration: gc.duration,
        status: gc.status,
        studentCount: gc.studentIds?.length || 0,
        createdAt: gc.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch group classes' });
  }
});

// ========================================
// ========= CHAT MANAGEMENT APIs =========
// ========================================

// Get All Conversations
app.get('/api/admin/chat/conversations', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [conversations, total] = await Promise.all([
      Conversation.find()
        .populate('teacherId', 'name email avatar')
        .populate('studentId', 'name email avatar')
        .sort({ lastMessageAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Conversation.countDocuments()
    ]);
    
    res.json({
      success: true,
      conversations: conversations.map(c => ({
        id: c._id.toString(),
        teacher: { id: c.teacherId?._id, name: c.teacherId?.name, email: c.teacherId?.email },
        student: { id: c.studentId?._id, name: c.studentId?.name, email: c.studentId?.email },
        lastMessage: c.lastMessage,
        lastMessageAt: c.lastMessageAt,
        createdAt: c.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch conversations' });
  }
});

// Get All Messages (with filters)
app.get('/api/admin/chat/messages', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const { page = 1, limit = 100, conversationId } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const query = conversationId ? { conversationId } : {};
    
    const [messages, total] = await Promise.all([
      Message.find(query)
        .populate('senderId', 'name role')
        .populate('receiverId', 'name role')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Message.countDocuments(query)
    ]);
    
    res.json({
      success: true,
      messages: messages.map(m => ({
        id: m._id.toString(),
        sender: m.senderId?.name,
        receiver: m.receiverId?.name,
        content: m.content,
        type: m.type,
        delivered: m.delivered,
        read: m.read,
        createdAt: m.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Chat Statistics
app.get('/api/admin/chat/stats', adminAuthRequired, requireAdminPermission('VIEW_ANALYTICS'), async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const [totalMessages, todayMessages, totalConversations, activeConversations] = await Promise.all([
      Message.countDocuments(),
      Message.countDocuments({ createdAt: { $gte: today } }),
      Conversation.countDocuments(),
      Conversation.countDocuments({ lastMessageAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } })
    ]);
    
    res.json({
      success: true,
      stats: {
        totalMessages,
        todayMessages,
        totalConversations,
        activeConversations
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch chat stats' });
  }
});

// ========================================
// ========= GAMES MANAGEMENT APIs =========
// ========================================

// Get Game Scores
app.get('/api/admin/games/scores', adminAuthRequired, requireAdminPermission('VIEW_ANALYTICS'), async (req, res) => {
  try {
    const { page = 1, limit = 50, gameType } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const query = gameType ? { gameType } : {};
    
    const [scores, total] = await Promise.all([
      GameScore.find(query)
        .populate('userId', 'name email role')
        .sort({ score: -1, playedAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      GameScore.countDocuments(query)
    ]);
    
    res.json({
      success: true,
      scores: scores.map(s => ({
        id: s._id.toString(),
        user: s.userId?.name,
        username: s.username,
        gameType: s.gameType,
        score: s.score,
        xpEarned: s.xpEarned,
        difficulty: s.difficulty,
        playedAt: s.playedAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch game scores' });
  }
});

// Get Leaderboard
app.get('/api/admin/games/leaderboard', adminAuthRequired, requireAdminPermission('VIEW_ANALYTICS'), async (req, res) => {
  try {
    const { gameType, limit = 100 } = req.query;
    
    const matchStage = gameType ? { gameType } : {};
    
    const leaderboard = await GameScore.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: '$userId',
          username: { $first: '$username' },
          totalScore: { $sum: '$score' },
          totalXP: { $sum: '$xpEarned' },
          gamesPlayed: { $sum: 1 },
          avgScore: { $avg: '$score' }
        }
      },
      { $sort: { totalXP: -1 } },
      { $limit: parseInt(limit) }
    ]);
    
    const enriched = await Promise.all(
      leaderboard.map(async (entry, index) => {
        const user = await User.findById(entry._id).select('name email role avatar').lean();
        return {
          rank: index + 1,
          userId: entry._id.toString(),
          name: user?.name || entry.username,
          email: user?.email,
          role: user?.role,
          avatar: user?.avatar,
          totalScore: entry.totalScore,
          totalXP: entry.totalXP,
          gamesPlayed: entry.gamesPlayed,
          avgScore: Math.round(entry.avgScore)
        };
      })
    );
    
    res.json({ success: true, leaderboard: enriched });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

// Game Statistics
app.get('/api/admin/games/stats', adminAuthRequired, requireAdminPermission('VIEW_ANALYTICS'), async (req, res) => {
  try {
    const [totalGames, uniquePlayers, avgScore, topGame] = await Promise.all([
      GameScore.countDocuments(),
      GameScore.distinct('userId').then(arr => arr.length),
      GameScore.aggregate([{ $group: { _id: null, avg: { $avg: '$score' } } }]),
      GameScore.aggregate([
        { $group: { _id: '$gameType', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 1 }
      ])
    ]);
    
    res.json({
      success: true,
      stats: {
        totalGames,
        uniquePlayers,
        avgScore: Math.round(avgScore[0]?.avg || 0),
        mostPopular: topGame[0]?._id || 'N/A'
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch game stats' });
  }
});

// ========================================
// ========= SECURITY MANAGEMENT APIs =========
// ========================================

// Get All Active Sessions
app.get('/api/admin/security/sessions', adminAuthRequired, requireAdminPermission('VIEW_SECURITY'), async (req, res) => {
  try {
    const sessions = await UserSession.find({ isActive: true })
      .populate('userId', 'name email role')
      .sort({ lastActivity: -1 })
      .limit(200)
      .lean();
    
    res.json({
      success: true,
      sessions: sessions.map(s => ({
        id: s._id.toString(),
        user: { name: s.userId?.name, email: s.userId?.email, role: s.userId?.role },
        deviceType: s.deviceType,
        ipAddress: s.ipAddress,
        location: s.location,
        lastActivity: s.lastActivity,
        createdAt: s.createdAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Get Blocked IPs (placeholder - implement IP blocking schema if needed)
app.get('/api/admin/security/blocked-ips', adminAuthRequired, requireAdminPermission('VIEW_SECURITY'), async (req, res) => {
  try {
    // Implement IP blocking collection if needed
    res.json({ success: true, blockedIps: [] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch blocked IPs' });
  }
});

// Security Event Logs
app.get('/api/admin/security/logs', adminAuthRequired, requireAdminPermission('VIEW_SECURITY'), async (req, res) => {
  try {
    const { page = 1, limit = 100 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [events, total] = await Promise.all([
      SecurityEvent.find()
        .populate('userId', 'name email')
        .populate('adminId', 'name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      SecurityEvent.countDocuments()
    ]);
    
    res.json({
      success: true,
      events: events.map(e => ({
        id: e._id.toString(),
        type: e.eventType,
        severity: e.severity,
        user: e.userId?.name,
        admin: e.adminId?.name,
        ipAddress: e.ipAddress,
        details: e.details,
        resolved: e.resolved,
        createdAt: e.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch security logs' });
  }
});

// 2FA Settings (placeholder)
app.get('/api/admin/security/2fa', adminAuthRequired, async (req, res) => {
  try {
    const admin = await AdminUser.findById(req.adminId).select('twoFactorEnabled');
    res.json({
      success: true,
      twoFactorEnabled: admin?.twoFactorEnabled || false
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch 2FA settings' });
  }
});



// Setup 2FA - Generate secret and QR code
app.post('/api/admin/security/2fa/setup', adminAuthRequired, async (req, res) => {
  try {
    const admin = await AdminUser.findById(req.adminId);
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    if (admin.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is already enabled' });
    }
    
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Alarmind Admin (${admin.email})`,
      issuer: 'Alarmind'
    });
    
    // Store temporary secret (not enabled yet)
    admin.twoFactorTempSecret = secret.base32;
    await admin.save();
    
    // ===== REPLACE FROM HERE =====
    // Generate QR code with error handling
    let qrCodeUrl;
    try {
      qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    } catch (qrError) {
      console.error('QR code generation failed:', qrError);
      qrCodeUrl = null;
    }
    
    res.json({
      success: true,
      secret: secret.base32,
      qrCodeUrl: qrCodeUrl,
      otpauthUrl: secret.otpauth_url
    });
    // ===== TO HERE =====
    
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({ error: 'Failed to setup 2FA' });
  }
});

// Verify and Enable 2FA
app.post('/api/admin/security/2fa/verify', adminAuthRequired, async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code || code.length !== 6) {
      return res.status(400).json({ error: 'Valid 6-digit code required' });
    }
    
    const admin = await AdminUser.findById(req.adminId);
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    if (!admin.twoFactorTempSecret) {
      return res.status(400).json({ error: 'Please setup 2FA first' });
    }
    
    // Verify the code
    const verified = speakeasy.totp.verify({
      secret: admin.twoFactorTempSecret,
      encoding: 'base32',
      token: code,
      window: 2 // Allow 2 intervals tolerance
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Invalid code' });
    }
    
    // Generate backup codes
    const backupCodes = generateBackupCodes(10);
    const hashedBackupCodes = backupCodes.map(c => ({ code: c, used: false }));
    
    // Enable 2FA
    admin.twoFactorEnabled = true;
    admin.twoFactorSecret = admin.twoFactorTempSecret;
    admin.twoFactorTempSecret = undefined;
    admin.twoFactorBackupCodes = hashedBackupCodes;
    await admin.save();
    
    await logAdminAction(req.adminId, req.adminEmail, 'ENABLE_2FA', 'AUTH', null, {}, req);
    
    res.json({
      success: true,
      message: '2FA enabled successfully',
      backupCodes: backupCodes
    });
  } catch (error) {
    console.error('2FA verify error:', error);
    res.status(500).json({ error: 'Failed to verify 2FA' });
  }
});

// Disable 2FA
app.post('/api/admin/security/2fa/disable', adminAuthRequired, async (req, res) => {
  try {
    const { code, isBackupCode } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Code required' });
    }
    
    const admin = await AdminUser.findById(req.adminId);
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    if (!admin.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is not enabled' });
    }
    
    let verified = false;
    
    if (isBackupCode) {
      // Check backup codes
      const backupCode = admin.twoFactorBackupCodes.find(bc => bc.code === code && !bc.used);
      if (backupCode) {
        verified = true;
        backupCode.used = true;
      }
    } else {
      // Verify TOTP code
      verified = speakeasy.totp.verify({
        secret: admin.twoFactorSecret,
        encoding: 'base32',
        token: code,
        window: 2
      });
    }
    
    if (!verified) {
      return res.status(401).json({ error: 'Invalid code' });
    }
    
    // Disable 2FA
    admin.twoFactorEnabled = false;
    admin.twoFactorSecret = undefined;
    admin.twoFactorBackupCodes = [];
    await admin.save();
    
    await logAdminAction(req.adminId, req.adminEmail, 'DISABLE_2FA', 'AUTH', null, {}, req);
    
    res.json({ success: true, message: '2FA disabled' });
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

// Regenerate Backup Codes
app.post('/api/admin/security/2fa/backup-codes/regenerate', adminAuthRequired, async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code || code.length !== 6) {
      return res.status(400).json({ error: 'Valid 6-digit code required' });
    }
    
    const admin = await AdminUser.findById(req.adminId);
    if (!admin || !admin.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is not enabled' });
    }
    
    // Verify TOTP code
    const verified = speakeasy.totp.verify({
      secret: admin.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 2
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Invalid code' });
    }
    
    // Generate new backup codes
    const backupCodes = generateBackupCodes(10);
    admin.twoFactorBackupCodes = backupCodes.map(c => ({ code: c, used: false }));
    await admin.save();
    
    await logAdminAction(req.adminId, req.adminEmail, 'REGENERATE_BACKUP_CODES', 'AUTH', null, {}, req);
    
    res.json({ success: true, backupCodes });
  } catch (error) {
    console.error('Regenerate backup codes error:', error);
    res.status(500).json({ error: 'Failed to regenerate backup codes' });
  }
});

// Get all notifications
app.get('/api/admin/notifications', adminAuthRequired, requireAdminPermission('SEND_NOTIFICATIONS'), async (req, res) => {
  try {
    const notifications = await PushNotificationModel.find()
      .populate('createdBy', 'name email')
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();
    
    res.json({
      success: true,
      notifications: notifications.map(n => ({
        id: n._id.toString(),
        title: n.title,
        body: n.body,
        type: n.type,
        status: n.status,
        sentCount: n.sentCount,
        openedCount: n.openedCount,
        createdAt: n.createdAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// Broadcast notification (alias for existing send)
app.post('/api/admin/notifications/broadcast', adminAuthRequired, requireAdminPermission('SEND_NOTIFICATIONS'), async (req, res) => {
  // Same as /api/admin/push-notifications/send
  return app._router.handle(Object.assign(req, { url: '/api/admin/push-notifications/send' }), res);
});

// Notification stats
app.get('/api/admin/notifications/stats', adminAuthRequired, requireAdminPermission('SEND_NOTIFICATIONS'), async (req, res) => {
  try {
    const stats = await PushNotificationModel.aggregate([
      {
        $group: {
          _id: null,
          totalSent: { $sum: '$sentCount' },
          totalOpened: { $sum: '$openedCount' },
          avgOpenRate: { $avg: { $cond: [{ $gt: ['$sentCount', 0] }, { $divide: ['$openedCount', '$sentCount'] }, 0] } }
        }
      }
    ]);
    
    res.json({
      success: true,
      stats: {
        totalSent: stats[0]?.totalSent || 0,
        totalOpened: stats[0]?.totalOpened || 0,
        openRate: ((stats[0]?.avgOpenRate || 0) * 100).toFixed(1)
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notification stats' });
  }
});

// ========= USER MANAGEMENT =========

// List Users (with pagination, search, filters)
app.get('/api/admin/users', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      search, 
      role, 
      status,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;
    
    const query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { studentCode: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (role) query.role = role;
    if (status === 'active') query.isActive = true;
    if (status === 'inactive') query.isActive = false;
    if (status === 'online') query.isOnline = true;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;
    
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-passwordHash')
        .sort(sortOptions)
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      User.countDocuments(query)
    ]);
    
    const formatted = users.map(u => ({
      id: u._id.toString(),
      name: u.name,
      email: u.email,
      mobile: u.mobile,
      role: u.role,
      studentCode: u.studentCode,
      avatar: u.avatar,
      isActive: u.isActive,
      isOnline: u.isOnline,
      lastSeen: u.lastSeen,
      lastLogin: u.lastLogin,
      subscriptionStatus: u.subscriptionStatus,
      subscriptionExpiry: u.subscriptionExpiry,
      totalGameXP: u.totalGameXP,
      gamesPlayed: u.gamesPlayed,
      createdAt: u.createdAt
    }));
    
    await logAdminAction(req.adminId, req.adminEmail, 'LIST_USERS', 'USERS', null, 
      { page, limit, search, role, status }, req
    );
    
    res.json({
      success: true,
      users: formatted,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('List users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get Single User Details
app.get('/api/admin/users/:id', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-passwordHash').lean();
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get additional stats based on role
    let stats = {};
    
    if (user.role === 'TEACHER') {
      const [studentCount, classCount, assignmentCount, examCount] = await Promise.all([
        TeacherStudentLink.countDocuments({ teacherId: user._id, isActive: true }),
        ClassModel.countDocuments({ teacherId: user._id }),
        Assignment.countDocuments({ teacherId: user._id }),
        Exam.countDocuments({ teacherId: user._id })
      ]);
      
      stats = { studentCount, classCount, assignmentCount, examCount };
    } else {
      const [teacherCount, resultCount, attendanceCount] = await Promise.all([
        TeacherStudentLink.countDocuments({ studentId: user._id, isActive: true }),
        Result.countDocuments({ studentId: user._id }),
        Attendance.countDocuments({ 'marks.studentId': user._id })
      ]);
      
      stats = { teacherCount, resultCount, attendanceCount };
    }
    
    await logAdminAction(req.adminId, req.adminEmail, 'VIEW_USER', 'USERS', req.params.id, 
      { email: user.email }, req
    );
    
    res.json({
      success: true,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        mobile: user.mobile,
        role: user.role,
        studentCode: user.studentCode,
        avatar: user.avatar,
        isActive: user.isActive,
        isOnline: user.isOnline,
        lastSeen: user.lastSeen,
        lastLogin: user.lastLogin,
        subscriptionStatus: user.subscriptionStatus,
        subscriptionExpiry: user.subscriptionExpiry,
        totalGameXP: user.totalGameXP,
        gamesPlayed: user.gamesPlayed,
        createdAt: user.createdAt,
        stats
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

// Update User
app.put('/api/admin/users/:id', adminAuthRequired, requireAdminPermission('EDIT_USERS'), async (req, res) => {
  try {
    const { name, email, mobile, isActive, subscriptionStatus, subscriptionExpiry } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const changes = {};
    
    if (name && name !== user.name) {
      changes.name = { from: user.name, to: name };
      user.name = name;
    }
    if (email && email !== user.email) {
      changes.email = { from: user.email, to: email };
      user.email = email.toLowerCase();
    }
    if (mobile !== undefined) {
      changes.mobile = { from: user.mobile, to: mobile };
      user.mobile = mobile;
    }
    if (isActive !== undefined && isActive !== user.isActive) {
      changes.isActive = { from: user.isActive, to: isActive };
      user.isActive = isActive;
    }
    if (subscriptionStatus) {
      changes.subscriptionStatus = { from: user.subscriptionStatus, to: subscriptionStatus };
      user.subscriptionStatus = subscriptionStatus;
    }
    if (subscriptionExpiry) {
      changes.subscriptionExpiry = { from: user.subscriptionExpiry, to: subscriptionExpiry };
      user.subscriptionExpiry = new Date(subscriptionExpiry);
    }
    
    await user.save();
    
    await logAdminAction(req.adminId, req.adminEmail, 'UPDATE_USER', 'USERS', req.params.id, 
      { changes }, req
    );
    
    res.json({ success: true, message: 'User updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Deactivate User
app.post('/api/admin/users/:id/deactivate', adminAuthRequired, requireAdminPermission('EDIT_USERS'), async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isActive: false, isOnline: false },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await logAdminAction(req.adminId, req.adminEmail, 'DEACTIVATE_USER', 'USERS', req.params.id, 
      { email: user.email }, req
    );
    
    res.json({ success: true, message: 'User deactivated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to deactivate user' });
  }
});

// Activate User
app.post('/api/admin/users/:id/activate', adminAuthRequired, requireAdminPermission('EDIT_USERS'), async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isActive: true },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await logAdminAction(req.adminId, req.adminEmail, 'ACTIVATE_USER', 'USERS', req.params.id, 
      { email: user.email }, req
    );
    
    res.json({ success: true, message: 'User activated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to activate user' });
  }
});

// Reset User Password
app.post('/api/admin/users/:id/reset-password', adminAuthRequired, requireAdminPermission('EDIT_USERS'), async (req, res) => {
  try {
    const { newPassword } = req.body;
    
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.passwordHash = await bcrypt.hash(newPassword, 12);
    await user.save();
    
    await logAdminAction(req.adminId, req.adminEmail, 'RESET_USER_PASSWORD', 'USERS', req.params.id, 
      { email: user.email }, req
    );
    
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ========= ADMIN MANAGEMENT =========

// List Admins
app.get('/api/admin/admins', adminAuthRequired, requireAdminRole(['SUPER_ADMIN']), async (req, res) => {
  try {
    const admins = await AdminUser.find()
      .select('-passwordHash -twoFactorSecret')
      .sort({ createdAt: -1 })
      .lean();
    
    const formatted = admins.map(a => ({
      id: a._id.toString(),
      email: a.email,
      name: a.name,
      role: a.role,
      permissions: a.permissions,
      avatar: a.avatar,
      isActive: a.isActive,
      twoFactorEnabled: a.twoFactorEnabled,
      lastLogin: a.lastLogin,
      createdAt: a.createdAt
    }));
    
    res.json({ success: true, admins: formatted });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

// Create Admin
app.post('/api/admin/admins', adminAuthRequired, requireAdminRole(['SUPER_ADMIN']), async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    
    if (!email || !password || !name || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 12) {
      return res.status(400).json({ error: 'Password must be at least 12 characters' });
    }
    
    const existing = await AdminUser.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ error: 'Admin with this email already exists' });
    }
    
    const passwordHash = await bcrypt.hash(password, 12);
    const permissions = getDefaultPermissions(role);
    
    const admin = await AdminUser.create({
      email: email.toLowerCase(),
      passwordHash,
      name,
      role,
      permissions,
      createdBy: req.adminId
    });
    
    await logAdminAction(req.adminId, req.adminEmail, 'CREATE_ADMIN', 'ADMINS', admin._id.toString(), 
      { email: admin.email, role: admin.role }, req
    );
    
    res.status(201).json({ 
      success: true, 
      adminId: admin._id.toString(),
      message: 'Admin created successfully'
    });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

// Update Admin
app.put('/api/admin/admins/:id', adminAuthRequired, requireAdminRole(['SUPER_ADMIN']), async (req, res) => {
  try {
    const { name, role, permissions, isActive } = req.body;
    
    const admin = await AdminUser.findById(req.params.id);
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    // Prevent editing yourself
    if (admin._id.toString() === req.adminId) {
      return res.status(400).json({ error: 'Cannot edit your own account here' });
    }
    
    if (name) admin.name = name;
    if (role) {
      admin.role = role;
      admin.permissions = permissions || getDefaultPermissions(role);
    }
    if (isActive !== undefined) admin.isActive = isActive;
    admin.updatedAt = new Date();
    
    await admin.save();
    
    await logAdminAction(req.adminId, req.adminEmail, 'UPDATE_ADMIN', 'ADMINS', req.params.id, 
      { email: admin.email, changes: { name, role, isActive } }, req
    );
    
    res.json({ success: true, message: 'Admin updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update admin' });
  }
});

// ========================================
// ========= PUSH NOTIFICATIONS APIs =========
// ========================================

// Get all notifications (with pagination)
app.get('/api/admin/push-notifications', adminAuthRequired, requireAdminPermission('SEND_NOTIFICATIONS'), async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const query = {};
    if (status) query.status = status;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [notifications, total] = await Promise.all([
      PushNotificationModel.find(query)
        .populate('createdBy', 'name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      PushNotificationModel.countDocuments(query)
    ]);
    
    res.json({
      success: true,
      notifications: notifications.map(n => ({
        id: n._id.toString(),
        title: n.title,
        body: n.body,
        imageUrl: n.imageUrl,
        type: n.type,
        targetType: n.targetType,
        targetUserIds: n.targetUserIds,
        scheduledAt: n.scheduledAt,
        sentAt: n.sentAt,
        status: n.status,
        sentCount: n.sentCount,
        openedCount: n.openedCount,
        createdBy: n.createdBy?.name,
        createdAt: n.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// Send push notification
app.post('/api/admin/push-notifications/send', adminAuthRequired, requireAdminPermission('SEND_NOTIFICATIONS'), async (req, res) => {
  try {
    const { title, body, imageUrl, type, targetType, targetUserIds, scheduledAt, popupSettings, data } = req.body;
    
    if (!title || !body || !targetType) {
      return res.status(400).json({ error: 'Title, body, and target type are required' });
    }
    
    // Create notification record
    const notification = await PushNotificationModel.create({
      title,
      body,
      imageUrl,
      type: type || 'text',
      targetType,
      targetUserIds: targetType === 'specific' ? targetUserIds : [],
      popupSettings,
      data,
      scheduledAt: scheduledAt ? new Date(scheduledAt) : null,
      status: scheduledAt ? 'scheduled' : 'sent',
      sentAt: scheduledAt ? null : new Date(),
      createdBy: req.adminId
    });
    
    // If sending immediately, send to users
    if (!scheduledAt) {
      let targetUsers = [];
      
      if (targetType === 'all') {
        targetUsers = await User.find({ isActive: true }).select('_id fcmToken');
      } else if (targetType === 'teachers') {
        targetUsers = await User.find({ isActive: true, role: 'TEACHER' }).select('_id fcmToken');
      } else if (targetType === 'students') {
        targetUsers = await User.find({ isActive: true, role: 'STUDENT' }).select('_id fcmToken');
      } else if (targetType === 'specific' && targetUserIds?.length > 0) {
        targetUsers = await User.find({ _id: { $in: targetUserIds }, isActive: true }).select('_id fcmToken');
      }
      
      // Emit to connected users via socket
      for (const user of targetUsers) {
        io.to(user._id.toString()).emit('push_notification', {
          id: notification._id.toString(),
          title,
          body,
          imageUrl,
          type,
          data,
          popupSettings
        });
        
        // Create in-app notification
        await Notification.create({
          userId: user._id,
          type: 'SYSTEM',
          title,
          message: body,
          data: { notificationId: notification._id, ...data }
        });
      }
      
      notification.sentCount = targetUsers.length;
      await notification.save();
    }
    
    await logAdminAction(req.adminId, req.adminEmail, 'SEND_NOTIFICATION', 'NOTIFICATIONS', notification._id.toString(),
      { title, targetType, targetCount: notification.sentCount }, req);
    
    res.status(201).json({
      success: true,
      notificationId: notification._id.toString(),
      sentCount: notification.sentCount,
      message: scheduledAt ? 'Notification scheduled successfully' : 'Notification sent successfully'
    });
  } catch (error) {
    console.error('Send notification error:', error);
    res.status(500).json({ error: 'Failed to send notification' });
  }
});

// Delete notification
app.delete('/api/admin/push-notifications/:id', adminAuthRequired, requireAdminPermission('MANAGE_NOTIFICATIONS'), async (req, res) => {
  try {
    const notification = await PushNotificationModel.findByIdAndDelete(req.params.id);
    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    await logAdminAction(req.adminId, req.adminEmail, 'DELETE_NOTIFICATION', 'NOTIFICATIONS', req.params.id, {}, req);
    res.json({ success: true, message: 'Notification deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete notification' });
  }
});

// Get notification analytics
app.get('/api/admin/push-notifications/analytics', adminAuthRequired, requireAdminPermission('SEND_NOTIFICATIONS'), async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    
    const [totalSent, delivered, opened, recentNotifications] = await Promise.all([
      PushNotificationModel.aggregate([
        { $match: { status: 'sent', sentAt: { $gte: thirtyDaysAgo } } },
        { $group: { _id: null, total: { $sum: '$sentCount' } } }
      ]),
      PushNotificationModel.aggregate([
        { $match: { status: 'sent', sentAt: { $gte: thirtyDaysAgo } } },
        { $group: { _id: null, total: { $sum: '$deliveredCount' } } }
      ]),
      PushNotificationModel.aggregate([
        { $match: { status: 'sent', sentAt: { $gte: thirtyDaysAgo } } },
        { $group: { _id: null, total: { $sum: '$openedCount' } } }
      ]),
      PushNotificationModel.countDocuments({ sentAt: { $gte: thirtyDaysAgo } })
    ]);
    
    res.json({
      success: true,
      analytics: {
        totalSent: totalSent[0]?.total || 0,
        delivered: delivered[0]?.total || 0,
        opened: opened[0]?.total || 0,
        recentNotifications,
        deliveryRate: totalSent[0]?.total ? ((delivered[0]?.total || 0) / totalSent[0].total * 100).toFixed(1) : 0,
        openRate: delivered[0]?.total ? ((opened[0]?.total || 0) / delivered[0].total * 100).toFixed(1) : 0
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// ========================================
// ========= SUPPORT CHAT APIs =========
// ========================================

// Get all support tickets
app.get('/api/admin/support/tickets', adminAuthRequired, requireAdminPermission('VIEW_SUPPORT'), async (req, res) => {
  try {
    const { page = 1, limit = 20, status, priority } = req.query;
    const query = {};
    if (status) query.status = status;
    if (priority) query.priority = priority;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [tickets, total] = await Promise.all([
      SupportTicket.find(query)
        .populate('userId', 'name email role avatar')
        .populate('assignedTo', 'name email')
        .sort({ lastMessageAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      SupportTicket.countDocuments(query)
    ]);
    
    res.json({
      success: true,
      tickets: tickets.map(t => ({
        id: t._id.toString(),
        ticketNumber: t.ticketNumber,
        user: t.userId ? {
          id: t.userId._id.toString(),
          name: t.userId.name,
          email: t.userId.email,
          role: t.userId.role,
          avatar: t.userId.avatar
        } : null,
        subject: t.subject,
        status: t.status,
        priority: t.priority,
        assignedTo: t.assignedTo?.name,
        lastMessageAt: t.lastMessageAt,
        unreadCount: t.unreadAdminCount,
        createdAt: t.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    console.error('Get tickets error:', error);
    res.status(500).json({ error: 'Failed to fetch tickets' });
  }
});

// Get ticket messages
app.get('/api/admin/support/tickets/:id/messages', adminAuthRequired, requireAdminPermission('VIEW_SUPPORT'), async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id)
      .populate('userId', 'name email role avatar');
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    const messages = await SupportMessage.find({ ticketId: req.params.id })
      .sort({ createdAt: 1 })
      .lean();
    
    // Mark messages as read
    await SupportMessage.updateMany(
      { ticketId: req.params.id, senderType: 'user', isRead: false },
      { isRead: true }
    );
    ticket.unreadAdminCount = 0;
    await ticket.save();
    
    res.json({
      success: true,
      ticket: {
        id: ticket._id.toString(),
        ticketNumber: ticket.ticketNumber,
        user: ticket.userId ? {
          id: ticket.userId._id.toString(),
          name: ticket.userId.name,
          email: ticket.userId.email,
          role: ticket.userId.role,
          avatar: ticket.userId.avatar
        } : null,
        subject: ticket.subject,
        status: ticket.status,
        priority: ticket.priority
      },
      messages: messages.map(m => ({
        id: m._id.toString(),
        senderId: m.senderId,
        senderType: m.senderType,
        senderName: m.senderName,
        content: m.content,
        attachmentUrl: m.attachmentUrl,
        isRead: m.isRead,
        createdAt: m.createdAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Reply to ticket
app.post('/api/admin/support/tickets/:id/reply', adminAuthRequired, requireAdminPermission('REPLY_SUPPORT'), async (req, res) => {
  try {
    const { content, attachmentUrl } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'Message content is required' });
    }
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    const admin = await AdminUser.findById(req.adminId);
    
    const message = await SupportMessage.create({
      ticketId: ticket._id,
      senderId: req.adminId,
      senderType: 'admin',
      senderName: admin.name,
      content,
      attachmentUrl
    });
    
    ticket.lastMessageAt = new Date();
    ticket.unreadUserCount += 1;
    if (ticket.status === 'open') ticket.status = 'in_progress';
    if (!ticket.assignedTo) ticket.assignedTo = req.adminId;
    await ticket.save();
    
    // Notify user via socket
    io.to(ticket.userId.toString()).emit('support_message', {
      ticketId: ticket._id.toString(),
      message: {
        id: message._id.toString(),
        senderName: admin.name,
        content,
        createdAt: message.createdAt
      }
    });
    
    await logAdminAction(req.adminId, req.adminEmail, 'REPLY_SUPPORT_TICKET', 'SUPPORT', req.params.id, 
      { ticketNumber: ticket.ticketNumber }, req);
    
    res.status(201).json({
      success: true,
      message: {
        id: message._id.toString(),
        content,
        createdAt: message.createdAt
      }
    });
  } catch (error) {
    console.error('Reply ticket error:', error);
    res.status(500).json({ error: 'Failed to send reply' });
  }
});

// Update ticket status
app.put('/api/admin/support/tickets/:id/status', adminAuthRequired, requireAdminPermission('REPLY_SUPPORT'), async (req, res) => {
  try {
    const { status, priority } = req.body;
    
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    if (status) ticket.status = status;
    if (priority) ticket.priority = priority;
    ticket.updatedAt = new Date();
    await ticket.save();
    
    await logAdminAction(req.adminId, req.adminEmail, 'UPDATE_TICKET_STATUS', 'SUPPORT', req.params.id,
      { status, priority }, req);
    
    res.json({ success: true, message: 'Ticket updated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update ticket' });
  }
});

// ========================================
// ========= LEGAL DOCUMENTS APIs =========
// ========================================

// Get all legal documents
app.get('/api/admin/legal', adminAuthRequired, requireAdminPermission('MANAGE_LEGAL'), async (req, res) => {
  try {
    const documents = await LegalDocument.find()
      .populate('createdBy', 'name')
      .sort({ type: 1 })
      .lean();
    
    res.json({
      success: true,
      documents: documents.map(d => ({
        id: d._id.toString(),
        type: d.type,
        title: d.title,
        content: d.content,
        version: d.version,
        isPublished: d.isPublished,
        publishedAt: d.publishedAt,
        createdBy: d.createdBy?.name,
        createdAt: d.createdAt,
        updatedAt: d.updatedAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch documents' });
  }
});

// Get document version history
app.get('/api/admin/legal/:type/history', adminAuthRequired, requireAdminPermission('MANAGE_LEGAL'), async (req, res) => {
  try {
    const versions = await LegalDocumentVersion.find({ documentType: req.params.type })
      .populate('createdBy', 'name')
      .sort({ createdAt: -1 })
      .lean();
    
    res.json({
      success: true,
      versions: versions.map(v => ({
        id: v._id.toString(),
        version: v.version,
        changeLog: v.changeLog,
        createdBy: v.createdBy?.name,
        createdAt: v.createdAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Update legal document
app.put('/api/admin/legal/:type', adminAuthRequired, requireAdminPermission('MANAGE_LEGAL'), async (req, res) => {
  try {
    const { title, content, version, changeLog } = req.body;
    
    if (!content || !version) {
      return res.status(400).json({ error: 'Content and version are required' });
    }
    
    let document = await LegalDocument.findOne({ type: req.params.type });
    
    if (document) {
      // Save current version to history
      await LegalDocumentVersion.create({
        documentType: req.params.type,
        version: document.version,
        content: document.content,
        changeLog: changeLog || 'Updated',
        createdBy: req.adminId
      });
      
      document.title = title || document.title;
      document.content = content;
      document.version = version;
      document.updatedAt = new Date();
      document.createdBy = req.adminId;
      await document.save();
    } else {
      document = await LegalDocument.create({
        type: req.params.type,
        title: title || req.params.type.replace('_', ' ').toUpperCase(),
        content,
        version,
        createdBy: req.adminId
      });
    }
    
    await logAdminAction(req.adminId, req.adminEmail, 'UPDATE_LEGAL_DOCUMENT', 'LEGAL', req.params.type,
      { version, changeLog }, req);
    
    res.json({ success: true, message: 'Document saved' });
  } catch (error) {
    console.error('Update legal doc error:', error);
    res.status(500).json({ error: 'Failed to update document' });
  }
});

// Publish legal document
app.post('/api/admin/legal/:type/publish', adminAuthRequired, requireAdminPermission('PUBLISH_LEGAL'), async (req, res) => {
  try {
    const document = await LegalDocument.findOne({ type: req.params.type });
    
    if (!document) {
      return res.status(404).json({ error: 'Document not found' });
    }
    
    document.isPublished = true;
    document.publishedAt = new Date();
    await document.save();
    
    await logAdminAction(req.adminId, req.adminEmail, 'PUBLISH_LEGAL_DOCUMENT', 'LEGAL', req.params.type,
      { version: document.version }, req);
    
    res.json({ success: true, message: 'Document published' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to publish document' });
  }
});

// ========================================
// ========= FEATURE FLAGS APIs =========
// ========================================

// Get all feature flags
app.get('/api/admin/feature-flags', adminAuthRequired, requireAdminPermission('MANAGE_FEATURE_FLAGS'), async (req, res) => {
  try {
    const flags = await FeatureFlag.find().sort({ category: 1, name: 1 }).lean();
    
    res.json({
      success: true,
      flags: flags.map(f => ({
        id: f._id.toString(),
        key: f.key,
        name: f.name,
        description: f.description,
        isEnabled: f.isEnabled,
        targetAudience: f.targetAudience,
        rolloutPercentage: f.rolloutPercentage,
        category: f.category,
        updatedAt: f.updatedAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch feature flags' });
  }
});

// Create feature flag
app.post('/api/admin/feature-flags', adminAuthRequired, requireAdminPermission('MANAGE_FEATURE_FLAGS'), async (req, res) => {
  try {
    const { key, name, description, category } = req.body;
    
    if (!key || !name) {
      return res.status(400).json({ error: 'Key and name are required' });
    }
    
    const existing = await FeatureFlag.findOne({ key });
    if (existing) {
      return res.status(409).json({ error: 'Feature flag with this key already exists' });
    }
    
    const flag = await FeatureFlag.create({
      key,
      name,
      description,
      category: category || 'General',
      updatedBy: req.adminId
    });
    
    await logAdminAction(req.adminId, req.adminEmail, 'CREATE_FEATURE_FLAG', 'FEATURE_FLAGS', flag._id.toString(),
      { key, name }, req);
    
    res.status(201).json({ success: true, flagId: flag._id.toString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create feature flag' });
  }
});

// Toggle feature flag
app.put('/api/admin/feature-flags/:id/toggle', adminAuthRequired, requireAdminPermission('MANAGE_FEATURE_FLAGS'), async (req, res) => {
  try {
    const { isEnabled, rolloutPercentage, targetAudience } = req.body;
    
    const flag = await FeatureFlag.findById(req.params.id);
    if (!flag) {
      return res.status(404).json({ error: 'Feature flag not found' });
    }
    
    if (typeof isEnabled === 'boolean') flag.isEnabled = isEnabled;
    if (rolloutPercentage !== undefined) flag.rolloutPercentage = rolloutPercentage;
    if (targetAudience) flag.targetAudience = targetAudience;
    flag.updatedBy = req.adminId;
    flag.updatedAt = new Date();
    await flag.save();
    
    // Broadcast to all connected users
    io.emit('feature_flag_update', {
      key: flag.key,
      isEnabled: flag.isEnabled,
      rolloutPercentage: flag.rolloutPercentage
    });
    
    await logAdminAction(req.adminId, req.adminEmail, 'UPDATE_FEATURE_FLAG', 'FEATURE_FLAGS', req.params.id,
      { key: flag.key, isEnabled, rolloutPercentage }, req);
    
    res.json({ success: true, message: 'Feature flag updated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update feature flag' });
  }
});

// ========================================
// ========= APP CONFIGURATION APIs =========
// ========================================

// Get all app configs
app.get('/api/admin/app-config', adminAuthRequired, requireAdminPermission('MANAGE_APP_CONFIG'), async (req, res) => {
  try {
    const configs = await AppConfig.find().sort({ category: 1 }).lean();
    
    res.json({
      success: true,
      configs: configs.map(c => ({
        key: c.key,
        value: c.isSecret ? '••••••••' : c.value,
        type: c.type,
        category: c.category,
        description: c.description,
        isSecret: c.isSecret,
        updatedAt: c.updatedAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch configs' });
  }
});

// Update app config
app.put('/api/admin/app-config/:key', adminAuthRequired, requireAdminPermission('MANAGE_APP_CONFIG'), async (req, res) => {
  try {
    const { value, type, category, description } = req.body;
    
    const config = await AppConfig.findOneAndUpdate(
      { key: req.params.key },
      {
        value,
        type: type || 'string',
        category: category || 'General',
        description,
        updatedBy: req.adminId,
        updatedAt: new Date()
      },
      { upsert: true, new: true }
    );
    
    // Special handling for maintenance mode
    if (req.params.key === 'maintenance_mode' && value === true) {
      io.emit('maintenance_mode', { enabled: true, message: 'App is under maintenance' });
    }
    
    await logAdminAction(req.adminId, req.adminEmail, 'UPDATE_APP_CONFIG', 'APP_CONFIG', req.params.key,
      { category }, req);
    
    res.json({ success: true, message: 'Config updated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update config' });
  }
});

// Get maintenance status (public)
app.get('/api/maintenance-status', async (req, res) => {
  try {
    const maintenanceMode = await AppConfig.findOne({ key: 'maintenance_mode' });
    const maintenanceMessage = await AppConfig.findOne({ key: 'maintenance_message' });
    
    res.json({
      isMaintenanceMode: maintenanceMode?.value === true || maintenanceMode?.value === 'true',
      message: maintenanceMessage?.value || 'App is under maintenance. Please try again later.'
    });
  } catch (error) {
    res.json({ isMaintenanceMode: false });
  }
});

// ========================================
// ========= USER CONTROL APIs =========
// ========================================

// Block user
app.post('/api/admin/users/:id/block', adminAuthRequired, requireAdminPermission('BLOCK_USERS'), async (req, res) => {
  try {
    const { reason, banType, bannedUntil } = req.body;
    
    if (!reason) {
      return res.status(400).json({ error: 'Reason is required' });
    }
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Deactivate user
    user.isActive = false;
    user.isOnline = false;
    await user.save();
    
    // Create ban record
    await UserBan.create({
      userId: user._id,
      reason,
      banType: banType || 'temporary',
      bannedUntil: bannedUntil ? new Date(bannedUntil) : null,
      bannedBy: req.adminId
    });
    
    // Disconnect user socket
    const socketId = connectedUsers.get(req.params.id);
    if (socketId) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.emit('account_blocked', { reason });
        socket.disconnect(true);
      }
      connectedUsers.delete(req.params.id);
    }
    
    // Kill all active sessions
    await UserSession.updateMany({ userId: user._id }, { isActive: false });
    
    await logAdminAction(req.adminId, req.adminEmail, 'BLOCK_USER', 'USERS', req.params.id,
      { email: user.email, reason, banType, bannedUntil }, req);
    
    // Create security event
    await SecurityEvent.create({
      eventType: 'USER_BLOCKED',
      severity: 'medium',
      userId: user._id,
      adminId: req.adminId,
      ipAddress: req.ip,
      details: { reason, banType }
    });
    
    res.json({ success: true, message: 'User blocked successfully' });
  } catch (error) {
    console.error('Block user error:', error);
    res.status(500).json({ error: 'Failed to block user' });
  }
});

// Unblock user
app.post('/api/admin/users/:id/unblock', adminAuthRequired, requireAdminPermission('BLOCK_USERS'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.isActive = true;
    await user.save();
    
    // Update ban record
    await UserBan.findOneAndUpdate(
      { userId: user._id, isActive: true },
      { isActive: false, unbannedBy: req.adminId, unbannedAt: new Date() }
    );
    
    await logAdminAction(req.adminId, req.adminEmail, 'UNBLOCK_USER', 'USERS', req.params.id,
      { email: user.email }, req);
    
    res.json({ success: true, message: 'User unblocked' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to unblock user' });
  }
});

// Terminate user (permanent delete)
app.post('/api/admin/users/:id/terminate', adminAuthRequired, requireAdminPermission('TERMINATE_USERS'), async (req, res) => {
  try {
    // Only SUPER_ADMIN can terminate
    if (req.adminRole !== 'SUPER_ADMIN') {
      return res.status(403).json({ error: 'Only Super Admin can terminate users' });
    }
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userEmail = user.email;
    
    // Delete all user data
    await Promise.all([
      TeacherStudentLink.deleteMany({ $or: [{ teacherId: user._id }, { studentId: user._id }] }),
      Message.deleteMany({ $or: [{ senderId: user._id }, { receiverId: user._id }] }),
      Conversation.deleteMany({ $or: [{ teacherId: user._id }, { studentId: user._id }] }),
      Notification.deleteMany({ userId: user._id }),
      Result.deleteMany({ $or: [{ teacherId: user._id }, { studentId: user._id }] }),
      PlannerTask.deleteMany({ userId: user._id }),
      UserSession.deleteMany({ userId: user._id }),
      UserBan.deleteMany({ userId: user._id }),
      User.findByIdAndDelete(user._id)
    ]);
    
    await logAdminAction(req.adminId, req.adminEmail, 'TERMINATE_USER', 'USERS', req.params.id,
      { email: userEmail }, req);
    
    // Create security event
    await SecurityEvent.create({
      eventType: 'USER_TERMINATED',
      severity: 'high',
      adminId: req.adminId,
      ipAddress: req.ip,
      details: { userEmail }
    });
    
    res.json({ success: true, message: 'User terminated and all data deleted' });
  } catch (error) {
    console.error('Terminate user error:', error);
    res.status(500).json({ error: 'Failed to terminate user' });
  }
});

// Get user location by IP
app.get('/api/admin/users/:id/location', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get latest session with IP
    const session = await UserSession.findOne({ userId: user._id })
      .sort({ lastActivity: -1 })
      .lean();
    
    if (!session?.ipAddress) {
      return res.json({ success: true, location: null, message: 'No IP data available' });
    }
    
    // In production, use a real IP geolocation service (ip-api.com, ipstack, etc.)
    // This is a mock response
    const mockLocation = {
      ip: session.ipAddress,
      city: 'Mumbai',
      region: 'Maharashtra',
      country: 'India',
      countryCode: 'IN',
      latitude: 19.0760,
      longitude: 72.8777,
      isp: 'Jio Platforms Limited',
      timezone: 'Asia/Kolkata'
    };
    
    res.json({ success: true, location: mockLocation });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get location' });
  }
});

// Get user sessions
app.get('/api/admin/users/:id/sessions', adminAuthRequired, requireAdminPermission('VIEW_USERS'), async (req, res) => {
  try {
    const sessions = await UserSession.find({ userId: req.params.id, isActive: true })
      .sort({ lastActivity: -1 })
      .lean();
    
    res.json({
      success: true,
      sessions: sessions.map(s => ({
        id: s._id.toString(),
        deviceType: s.deviceType,
        deviceName: s.deviceName,
        ipAddress: s.ipAddress,
        location: s.location,
        lastActivity: s.lastActivity,
        createdAt: s.createdAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Kill user session
app.post('/api/admin/users/:userId/sessions/:sessionId/kill', adminAuthRequired, requireAdminPermission('BLOCK_USERS'), async (req, res) => {
  try {
    await UserSession.findByIdAndUpdate(req.params.sessionId, { isActive: false });
    
    // Disconnect socket if connected
    const socketId = connectedUsers.get(req.params.userId);
    if (socketId) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.emit('session_killed');
        socket.disconnect(true);
      }
    }
    
    await logAdminAction(req.adminId, req.adminEmail, 'KILL_USER_SESSION', 'USERS', req.params.userId,
      { sessionId: req.params.sessionId }, req);
    
    res.json({ success: true, message: 'Session terminated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to kill session' });
  }
});

// ========================================
// ========= SUBSCRIPTION APIs =========
// ========================================

// Get subscription plans
app.get('/api/admin/subscriptions/plans', adminAuthRequired, requireAdminPermission('MANAGE_SUBSCRIPTIONS'), async (req, res) => {
  try {
    const plans = await SubscriptionPlan.find().sort({ price: 1 }).lean();
    
    res.json({
      success: true,
      plans: plans.map(p => ({
        id: p._id.toString(),
        name: p.name,
        description: p.description,
        price: p.price,
        currency: p.currency,
        duration: p.duration,
        features: p.features,
        isActive: p.isActive,
        subscriberCount: p.subscriberCount,
        createdAt: p.createdAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch plans' });
  }
});

// Create subscription plan
app.post('/api/admin/subscriptions/plans', adminAuthRequired, requireAdminPermission('MANAGE_SUBSCRIPTIONS'), async (req, res) => {
  try {
    const { name, description, price, currency, duration, features } = req.body;
    
    if (!name || price === undefined || !duration) {
      return res.status(400).json({ error: 'Name, price, and duration are required' });
    }
    
    const plan = await SubscriptionPlan.create({
      name,
      description,
      price,
      currency: currency || 'INR',
      duration,
      features: features || [],
      createdBy: req.adminId
    });
    
    await logAdminAction(req.adminId, req.adminEmail, 'CREATE_SUBSCRIPTION_PLAN', 'SUBSCRIPTIONS', plan._id.toString(),
      { name, price }, req);
    
    res.status(201).json({ success: true, planId: plan._id.toString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create plan' });
  }
});

// Update subscription plan
app.put('/api/admin/subscriptions/plans/:id', adminAuthRequired, requireAdminPermission('MANAGE_SUBSCRIPTIONS'), async (req, res) => {
  try {
    const { name, description, price, features, isActive } = req.body;
    
    const plan = await SubscriptionPlan.findById(req.params.id);
    if (!plan) {
      return res.status(404).json({ error: 'Plan not found' });
    }
    
    if (name) plan.name = name;
    if (description !== undefined) plan.description = description;
    if (price !== undefined) plan.price = price;
    if (features) plan.features = features;
    if (typeof isActive === 'boolean') plan.isActive = isActive;
    plan.updatedAt = new Date();
    await plan.save();
    
    await logAdminAction(req.adminId, req.adminEmail, 'UPDATE_SUBSCRIPTION_PLAN', 'SUBSCRIPTIONS', req.params.id,
      { name, isActive }, req);
    
    res.json({ success: true, message: 'Plan updated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update plan' });
  }
});

// Get user subscriptions
app.get('/api/admin/subscriptions/users', adminAuthRequired, requireAdminPermission('MANAGE_SUBSCRIPTIONS'), async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const query = {};
    if (status) query.status = status;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [subscriptions, total] = await Promise.all([
      UserSubscription.find(query)
        .populate('userId', 'name email role')
        .populate('planId', 'name price duration')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      UserSubscription.countDocuments(query)
    ]);
    
    res.json({
      success: true,
      subscriptions: subscriptions.map(s => ({
        id: s._id.toString(),
        user: s.userId ? { id: s.userId._id.toString(), name: s.userId.name, email: s.userId.email } : null,
        plan: s.planId ? { name: s.planId.name, price: s.planId.price, duration: s.planId.duration } : null,
        status: s.status,
        startDate: s.startDate,
        endDate: s.endDate,
        amount: s.amount,
        paymentMethod: s.paymentMethod,
        createdAt: s.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch subscriptions' });
  }
});

// Get transactions
app.get('/api/admin/transactions', adminAuthRequired, requireAdminPermission('MANAGE_TRANSACTIONS'), async (req, res) => {
  try {
    const { page = 1, limit = 20, type, status } = req.query;
    const query = {};
    if (type) query.type = type;
    if (status) query.status = status;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .populate('userId', 'name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Transaction.countDocuments(query)
    ]);
    
    res.json({
      success: true,
      transactions: transactions.map(t => ({
        id: t._id.toString(),
        user: t.userId ? { name: t.userId.name, email: t.userId.email } : null,
        type: t.type,
        amount: t.amount,
        currency: t.currency,
        status: t.status,
        paymentMethod: t.paymentMethod,
        orderId: t.orderId,
        createdAt: t.createdAt
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Issue refund
app.post('/api/admin/transactions/:id/refund', adminAuthRequired, requireAdminPermission('ISSUE_REFUNDS'), async (req, res) => {
  try {
    const { reason } = req.body;
    
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    if (transaction.status !== 'completed') {
      return res.status(400).json({ error: 'Can only refund completed transactions' });
    }
    
    // Create refund transaction
    await Transaction.create({
      userId: transaction.userId,
      type: 'refund',
      amount: transaction.amount,
      currency: transaction.currency,
      status: 'completed',
      paymentMethod: transaction.paymentMethod,
      metadata: { originalTransactionId: transaction._id, reason }
    });
    
    transaction.status = 'refunded';
    await transaction.save();
    
    // Update user subscription if applicable
    if (transaction.subscriptionId) {
      await UserSubscription.findByIdAndUpdate(transaction.subscriptionId, { status: 'cancelled' });
      await User.findByIdAndUpdate(transaction.userId, { subscriptionStatus: 'free' });
    }
    
    await logAdminAction(req.adminId, req.adminEmail, 'ISSUE_REFUND', 'TRANSACTIONS', req.params.id,
      { amount: transaction.amount, reason }, req);
    
    res.json({ success: true, message: 'Refund issued successfully' });
  } catch (error) {
    console.error('Refund error:', error);
    res.status(500).json({ error: 'Failed to issue refund' });
  }
});

// Get promo codes
app.get('/api/admin/promo-codes', adminAuthRequired, requireAdminPermission('MANAGE_SUBSCRIPTIONS'), async (req, res) => {
  try {
    const codes = await PromoCode.find().sort({ createdAt: -1 }).lean();
    
    res.json({
      success: true,
      promoCodes: codes.map(c => ({
        id: c._id.toString(),
        code: c.code,
        discountType: c.discountType,
        discountValue: c.discountValue,
        maxUses: c.maxUses,
        usedCount: c.usedCount,
        validFrom: c.validFrom,
        validUntil: c.validUntil,
        isActive: c.isActive,
        createdAt: c.createdAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch promo codes' });
  }
});

// Create promo code
app.post('/api/admin/promo-codes', adminAuthRequired, requireAdminPermission('MANAGE_SUBSCRIPTIONS'), async (req, res) => {
  try {
    const { code, discountType, discountValue, maxUses, validUntil } = req.body;
    
    if (!code || !discountValue || !validUntil) {
      return res.status(400).json({ error: 'Code, discount value, and expiry are required' });
    }
    
    const existing = await PromoCode.findOne({ code: code.toUpperCase() });
    if (existing) {
      return res.status(409).json({ error: 'Promo code already exists' });
    }
    
    const promoCode = await PromoCode.create({
      code: code.toUpperCase(),
      discountType: discountType || 'percentage',
      discountValue,
      maxUses: maxUses || 100,
      validUntil: new Date(validUntil),
      createdBy: req.adminId
    });
    
    await logAdminAction(req.adminId, req.adminEmail, 'CREATE_PROMO_CODE', 'PROMO_CODES', promoCode._id.toString(),
      { code: promoCode.code }, req);
    
    res.status(201).json({ success: true, promoCodeId: promoCode._id.toString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create promo code' });
  }
});

// ========================================
// ========= SERVER MONITORING APIs =========
// ========================================

// Get server

// Delete Admin
app.delete('/api/admin/admins/:id', adminAuthRequired, requireAdminRole(['SUPER_ADMIN']), async (req, res) => {
  try {
    const admin = await AdminUser.findById(req.params.id);
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    if (admin._id.toString() === req.adminId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    await AdminSession.deleteMany({ adminId: admin._id });
    await AdminUser.findByIdAndDelete(req.params.id);
    
    await logAdminAction(req.adminId, req.adminEmail, 'DELETE_ADMIN', 'ADMINS', req.params.id, 
      { email: admin.email }, req
    );
    
    res.json({ success: true, message: 'Admin deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete admin' });
  }
});

// ========= AUDIT LOGS =========

app.get('/api/admin/audit-logs', adminAuthRequired, requireAdminPermission('VIEW_LOGS'), async (req, res) => {
  try {
    const { page = 1, limit = 50, adminId, action, resource, startDate, endDate } = req.query;
    
    const query = {};
    if (adminId) query.adminId = adminId;
    if (action) query.action = { $regex: action, $options: 'i' };
    if (resource) query.resource = resource;
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [logs, total] = await Promise.all([
      AdminAuditLog.find(query)
        .populate('adminId', 'name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      AdminAuditLog.countDocuments(query)
    ]);
    
    const formatted = logs.map(log => ({
      id: log._id.toString(),
      admin: log.adminId ? { id: log.adminId._id.toString(), name: log.adminId.name, email: log.adminId.email } : null,
      adminEmail: log.adminEmail,
      action: log.action,
      resource: log.resource,
      resourceId: log.resourceId,
      details: log.details,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      status: log.status,
      createdAt: log.createdAt
    }));
    
    res.json({
      success: true,
      logs: formatted,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// ========= REPORTS =========

app.get('/api/admin/reports/users', adminAuthRequired, requireAdminPermission('VIEW_REPORTS'), async (req, res) => {
  try {
    const { format = 'json', startDate, endDate } = req.query;
    
    const query = {};
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }
    
    const users = await User.find(query)
      .select('name email role studentCode isActive subscriptionStatus createdAt lastLogin')
      .sort({ createdAt: -1 })
      .lean();
    
    await logAdminAction(req.adminId, req.adminEmail, 'GENERATE_USER_REPORT', 'REPORTS', null, 
      { count: users.length, format }, req
    );
    
    if (format === 'csv') {
      const csv = [
        'Name,Email,Role,Student Code,Active,Subscription,Created At,Last Login',
        ...users.map(u => `${u.name},${u.email},${u.role},${u.studentCode || ''},${u.isActive},${u.subscriptionStatus},${u.createdAt},${u.lastLogin || ''}`)
      ].join('\n');
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=users_report.csv');
      return res.send(csv);
    }
    
    res.json({ success: true, users, count: users.length });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// ========= SYSTEM SETTINGS =========

app.get('/api/admin/settings', adminAuthRequired, requireAdminPermission('MANAGE_SETTINGS'), async (req, res) => {
  try {
    const settings = await SystemSettings.find().lean();
    
    const formatted = {};
    settings.forEach(s => {
      if (!formatted[s.category]) formatted[s.category] = {};
      formatted[s.category][s.key] = {
        value: s.value,
        description: s.description,
        updatedAt: s.updatedAt
      };
    });
    
    res.json({ success: true, settings: formatted });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/admin/settings/:key', adminAuthRequired, requireAdminPermission('MANAGE_SETTINGS'), async (req, res) => {
  try {
    const { value, category, description } = req.body;
    
    const setting = await SystemSettings.findOneAndUpdate(
      { key: req.params.key },
      { 
        value, 
        category: category || 'general',
        description,
        updatedBy: req.adminId,
        updatedAt: new Date()
      },
      { upsert: true, new: true }
    );
    
    await logAdminAction(req.adminId, req.adminEmail, 'UPDATE_SETTING', 'SETTINGS', req.params.key, 
      { value }, req
    );
    
    res.json({ success: true, setting });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update setting' });
  }
});

// ========= CREATE INITIAL SUPER ADMIN (ONE-TIME SETUP) =========
app.post('/api/admin/setup/initial', async (req, res) => {
  try {
    // Check if any admin exists
    const existingAdmin = await AdminUser.findOne();
    if (existingAdmin) {
      return res.status(400).json({ error: 'Setup already completed' });
    }
    
    const { email, password, name, setupKey } = req.body;
    
    // Require setup key for security
    if (setupKey !== process.env.ADMIN_SETUP_KEY && setupKey !== 'alarmind_admin_setup_2024') {
      return res.status(403).json({ error: 'Invalid setup key' });
    }
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }
    
    if (password.length < 12) {
      return res.status(400).json({ error: 'Password must be at least 12 characters' });
    }
    
    const passwordHash = await bcrypt.hash(password, 12);
    
    const admin = await AdminUser.create({
      email: email.toLowerCase(),
      passwordHash,
      name,
      role: 'SUPER_ADMIN',
      permissions: getDefaultPermissions('SUPER_ADMIN')
    });
    
    console.log(`🔐 Initial super admin created: ${email}`);
    
    res.status(201).json({ 
      success: true, 
      message: 'Super admin created successfully',
      adminId: admin._id.toString()
    });
  } catch (error) {
    console.error('Initial setup error:', error);
    res.status(500).json({ error: 'Setup failed' });
  }
});

// ========================================
// ========= USER-FACING APP APIs (For Mobile App) =========
// ========================================

// ========= SUPPORT TICKETS (User-facing) =========

// Create a support ticket (User)
app.post('/api/support/tickets', authRequired, async (req, res) => {
  try {
    const { subject, message, priority } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ error: 'Subject and message are required' });
    }
    
    // Generate ticket number
    const count = await SupportTicket.countDocuments();
    const ticketNumber = `TKT${String(count + 1).padStart(6, '0')}`;
    
    const ticket = await SupportTicket.create({
      ticketNumber,
      userId: req.userId,
      subject,
      priority: priority || 'medium',
      status: 'open'
    });
    
    // Create first message
    const user = await User.findById(req.userId).select('name');
    await SupportMessage.create({
      ticketId: ticket._id,
      senderId: req.userId,
      senderType: 'user',
      senderName: user?.name || 'User',
      content: message
    });
    
    res.status(201).json({
      success: true,
      ticketId: ticket._id.toString(),
      ticketNumber: ticket.ticketNumber
    });
  } catch (error) {
    console.error('Create ticket error:', error);
    res.status(500).json({ error: 'Failed to create ticket' });
  }
});

// Get my support tickets (User)
app.get('/api/support/tickets', authRequired, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.userId })
      .sort({ lastMessageAt: -1 })
      .lean();
    
    res.json({
      success: true,
      tickets: tickets.map(t => ({
        id: t._id.toString(),
        ticketNumber: t.ticketNumber,
        subject: t.subject,
        status: t.status,
        priority: t.priority,
        lastMessageAt: t.lastMessageAt,
        unreadUserCount: t.unreadUserCount || 0,
        createdAt: t.createdAt
      }))
    });
  } catch (error) {
    console.error('Get tickets error:', error);
    res.status(500).json({ error: 'Failed to fetch tickets' });
  }
});

// Get ticket details with messages (User)
app.get('/api/support/tickets/:ticketId', authRequired, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.ticketId,
      userId: req.userId
    }).lean();
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    const messages = await SupportMessage.find({ ticketId: ticket._id })
      .sort({ createdAt: 1 })
      .lean();
    
    // Mark as read
    await SupportTicket.findByIdAndUpdate(ticket._id, { unreadUserCount: 0 });
    await SupportMessage.updateMany(
      { ticketId: ticket._id, senderType: 'admin', isRead: false },
      { isRead: true }
    );
    
    res.json({
      success: true,
      ticket: {
        id: ticket._id.toString(),
        ticketNumber: ticket.ticketNumber,
        subject: ticket.subject,
        status: ticket.status,
        priority: ticket.priority,
        createdAt: ticket.createdAt
      },
      messages: messages.map(m => ({
        id: m._id.toString(),
        senderId: m.senderId,
        senderType: m.senderType,
        senderName: m.senderName,
        content: m.content,
        attachmentUrl: m.attachmentUrl,
        attachmentType: m.attachmentType,
        isRead: m.isRead,
        createdAt: m.createdAt
      }))
    });
  } catch (error) {
    console.error('Get ticket details error:', error);
    res.status(500).json({ error: 'Failed to fetch ticket' });
  }
});

// Send message to ticket (User)
app.post('/api/support/tickets/:ticketId/messages', authRequired, async (req, res) => {
  try {
    const { content, attachmentUrl, attachmentType } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'Message content is required' });
    }
    
    const ticket = await SupportTicket.findOne({
      _id: req.params.ticketId,
      userId: req.userId
    });
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    if (ticket.status === 'closed') {
      return res.status(400).json({ error: 'Cannot send message to closed ticket' });
    }
    
    const user = await User.findById(req.userId).select('name');
    
    const message = await SupportMessage.create({
      ticketId: ticket._id,
      senderId: req.userId,
      senderType: 'user',
      senderName: user?.name || 'User',
      content,
      attachmentUrl,
      attachmentType
    });
    
    // Update ticket
    ticket.lastMessageAt = new Date();
    ticket.unreadAdminCount = (ticket.unreadAdminCount || 0) + 1;
    if (ticket.status === 'resolved') {
      ticket.status = 'open'; // Reopen if user responds
    }
    await ticket.save();
    
    res.json({
      success: true,
      messageId: message._id.toString()
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Close ticket (User)
app.post('/api/support/tickets/:ticketId/close', authRequired, async (req, res) => {
  try {
    const ticket = await SupportTicket.findOne({
      _id: req.params.ticketId,
      userId: req.userId
    });
    
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    
    ticket.status = 'closed';
    ticket.updatedAt = new Date();
    await ticket.save();
    
    res.json({ success: true, message: 'Ticket closed' });
  } catch (error) {
    console.error('Close ticket error:', error);
    res.status(500).json({ error: 'Failed to close ticket' });
  }
});

// ========= LEGAL DOCUMENTS (Public) =========

// Get legal document by type
app.get('/api/legal/:type', async (req, res) => {
  try {
    const validTypes = ['privacy_policy', 'terms_conditions', 'refund_policy', 'cookie_policy', 'gdpr'];
    
    if (!validTypes.includes(req.params.type)) {
      return res.status(400).json({ error: 'Invalid document type' });
    }
    
    const document = await LegalDocument.findOne({
      type: req.params.type,
      isPublished: true
    }).lean();
    
    if (!document) {
      return res.status(404).json({ error: 'Document not found' });
    }
    
    res.json({
      success: true,
      document: {
        type: document.type,
        title: document.title,
        content: document.content,
        version: document.version,
        publishedAt: document.publishedAt
      }
    });
  } catch (error) {
    console.error('Get legal document error:', error);
    res.status(500).json({ error: 'Failed to fetch document' });
  }
});

// Get all legal documents
app.get('/api/legal', async (req, res) => {
  try {
    const documents = await LegalDocument.find({ isPublished: true })
      .select('type title version publishedAt')
      .lean();
    
    res.json({
      success: true,
      documents: documents.map(d => ({
        type: d.type,
        title: d.title,
        version: d.version,
        publishedAt: d.publishedAt
      }))
    });
  } catch (error) {
    console.error('Get legal documents error:', error);
    res.status(500).json({ error: 'Failed to fetch documents' });
  }
});

// ========= FEATURE FLAGS (User-facing) =========

// Get all feature flags for user
app.get('/api/app/feature-flags', authRequired, async (req, res) => {
  try {
    const flags = await FeatureFlag.find({ isEnabled: true }).lean();
    
    const result = {};
    flags.forEach(flag => {
      result[flag.key] = {
        key: flag.key,
        name: flag.name,
        isEnabled: flag.isEnabled,
        targetAudience: flag.targetAudience
      };
    });
    
    res.json({ success: true, flags: result });
  } catch (error) {
    console.error('Get feature flags error:', error);
    res.status(500).json({ error: 'Failed to fetch feature flags' });
  }
});

// Get single feature flag
app.get('/api/app/feature-flags/:key', authRequired, async (req, res) => {
  try {
    const flag = await FeatureFlag.findOne({ key: req.params.key }).lean();
    
    if (!flag) {
      return res.json({ success: true, flag: { key: req.params.key, isEnabled: true } });
    }
    
    res.json({
      success: true,
      flag: {
        key: flag.key,
        name: flag.name,
        isEnabled: flag.isEnabled,
        targetAudience: flag.targetAudience
      }
    });
  } catch (error) {
    console.error('Get feature flag error:', error);
    res.status(500).json({ error: 'Failed to fetch feature flag' });
  }
});

// ========= APP CONFIG (User-facing) =========

// Get app config (non-secret values only)
app.get('/api/app/config', async (req, res) => {
  try {
    const configs = await AppConfig.find({ isSecret: false }).lean();
    
    const result = {};
    configs.forEach(c => {
      result[c.key] = c.value;
    });
    
    res.json({ success: true, configs: result });
  } catch (error) {
    console.error('Get app config error:', error);
    res.status(500).json({ error: 'Failed to fetch config' });
  }
});

// ========= USER SESSIONS (User-facing) =========

// Register session
app.post('/api/sessions/register', authRequired, async (req, res) => {
  try {
    const { deviceType, deviceName, userAgent } = req.body;
    
    const session = await UserSession.create({
      userId: req.userId,
      deviceType,
      deviceName,
      userAgent,
      ipAddress: req.ip || req.connection.remoteAddress,
      isActive: true
    });
    
    res.json({
      success: true,
      sessionId: session._id.toString()
    });
  } catch (error) {
    console.error('Register session error:', error);
    res.status(500).json({ error: 'Failed to register session' });
  }
});

// Get my sessions
app.get('/api/sessions', authRequired, async (req, res) => {
  try {
    const sessions = await UserSession.find({
      userId: req.userId,
      isActive: true
    }).sort({ lastActivity: -1 }).lean();
    
    res.json({
      success: true,
      sessions: sessions.map(s => ({
        id: s._id.toString(),
        deviceType: s.deviceType,
        deviceName: s.deviceName,
        ipAddress: s.ipAddress,
        location: s.location,
        lastActivity: s.lastActivity,
        createdAt: s.createdAt,
        isCurrent: false // Can be determined by comparing session tokens
      }))
    });
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Terminate session
app.delete('/api/sessions/:sessionId', authRequired, async (req, res) => {
  try {
    const session = await UserSession.findOne({
      _id: req.params.sessionId,
      userId: req.userId
    });
    
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    session.isActive = false;
    await session.save();
    
    res.json({ success: true, message: 'Session terminated' });
  } catch (error) {
    console.error('Terminate session error:', error);
    res.status(500).json({ error: 'Failed to terminate session' });
  }
});

// Session heartbeat
app.post('/api/sessions/heartbeat', authRequired, async (req, res) => {
  try {
    await UserSession.findOneAndUpdate(
      { userId: req.userId, isActive: true },
      { lastActivity: new Date() },
      { sort: { createdAt: -1 } }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Session heartbeat error:', error);
    res.status(500).json({ error: 'Failed to update session' });
  }
});

// ========================================
// ========= JITSI GROUP CALL APIs =========
// ========================================

// Generate unique room ID
const generateJitsiRoomId = () => {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let roomId = 'tm_'; // TuitionManager prefix
  for (let i = 0; i < 12; i++) {
    roomId += chars[Math.floor(Math.random() * chars.length)];
  }
  return roomId;
};

// Create Jitsi Room (Teacher only)
app.post('/api/jitsi/rooms', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { roomName, settings, scheduledAt, sectionId, studentIds, isForAllStudents, jitsiDomain } = req.body;
    
    if (!roomName) {
      return res.status(400).json({ error: 'Room name is required' });
    }
    
    const roomId = generateJitsiRoomId();
    
    const room = await JitsiRoom.create({
      roomId,
      roomName,
      teacherId: req.userId,
      settings: settings || {},
      scheduledAt: scheduledAt ? new Date(scheduledAt) : null,
      sectionId,
      studentIds: studentIds || [],
      isForAllStudents: isForAllStudents || false,
      jitsiDomain: jitsiDomain || 'meet.jit.si'
    });
    
    // Create teacher enrollment
    await JitsiEnrollment.create({
      roomId,
      userId: req.userId,
      role: 'TEACHER'
    });
    
    // If specific students, create their enrollments
    if (studentIds && studentIds.length > 0) {
      const enrollments = studentIds.map(studentId => ({
        roomId,
        userId: studentId,
        role: 'STUDENT'
      }));
      await JitsiEnrollment.insertMany(enrollments, { ordered: false }).catch(() => {});
    }
    
    // If for all students, enroll all linked students
    if (isForAllStudents) {
      const links = await TeacherStudentLink.find({ teacherId: req.userId, isActive: true });
      const enrollments = links.map(link => ({
        roomId,
        userId: link.studentId,
        role: 'STUDENT'
      }));
      await JitsiEnrollment.insertMany(enrollments, { ordered: false }).catch(() => {});
    }
    
    res.status(201).json({
      success: true,
      room: {
        id: room._id.toString(),
        roomId: room.roomId,
        roomName: room.roomName,
        settings: room.settings,
        isActive: room.isActive,
        jitsiDomain: room.jitsiDomain,
        scheduledAt: room.scheduledAt,
        createdAt: room.createdAt
      }
    });
  } catch (error) {
    console.error('Create Jitsi room error:', error);
    res.status(500).json({ error: 'Failed to create room' });
  }
});

// Get my Jitsi rooms (Teacher)
app.get('/api/jitsi/rooms', authRequired, async (req, res) => {
  try {
    let rooms;
    
    if (req.role === 'TEACHER') {
      rooms = await JitsiRoom.find({ teacherId: req.userId })
        .sort({ createdAt: -1 })
        .lean();
    } else {
      // Student: get rooms they're enrolled in
      const enrollments = await JitsiEnrollment.find({ 
        userId: req.userId, 
        kicked: false 
      }).select('roomId');
      
      const roomIds = enrollments.map(e => e.roomId);
      rooms = await JitsiRoom.find({ roomId: { $in: roomIds } })
        .populate('teacherId', 'name')
        .sort({ createdAt: -1 })
        .lean();
    }
    
    res.json({
      success: true,
      rooms: rooms.map(r => ({
        id: r._id.toString(),
        roomId: r.roomId,
        roomName: r.roomName,
        teacherName: r.teacherId?.name || 'Unknown',
        settings: r.settings,
        isActive: r.isActive,
        scheduledAt: r.scheduledAt,
        jitsiDomain: r.jitsiDomain,
        createdAt: r.createdAt
      }))
    });
  } catch (error) {
    console.error('Get Jitsi rooms error:', error);
    res.status(500).json({ error: 'Failed to fetch rooms' });
  }
});

// Get active rooms for student
app.get('/api/jitsi/rooms/active', authRequired, async (req, res) => {
  try {
    const enrollments = await JitsiEnrollment.find({ 
      userId: req.userId, 
      kicked: false 
    }).select('roomId');
    
    const roomIds = enrollments.map(e => e.roomId);
    
    const activeRooms = await JitsiRoom.find({ 
      roomId: { $in: roomIds },
      isActive: true
    })
    .populate('teacherId', 'name avatar')
    .lean();
    
    res.json({
      success: true,
      rooms: activeRooms.map(r => ({
        id: r._id.toString(),
        roomId: r.roomId,
        roomName: r.roomName,
        teacherName: r.teacherId?.name,
        teacherAvatar: r.teacherId?.avatar,
        settings: r.settings,
        jitsiDomain: r.jitsiDomain,
        startedAt: r.startedAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch active rooms' });
  }
});

// Start class (Teacher only) - Makes room active
app.post('/api/jitsi/rooms/:roomId/start', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId, teacherId: req.userId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    room.isActive = true;
    room.startedAt = new Date();
    room.updatedAt = new Date();
    await room.save();
    
    // Get all enrolled students
    const enrollments = await JitsiEnrollment.find({ 
      roomId: req.params.roomId, 
      role: 'STUDENT',
      kicked: false 
    }).select('userId');
    
    // Broadcast to all enrolled students via Socket.IO
    enrollments.forEach(enrollment => {
      io.to(enrollment.userId.toString()).emit('jitsi-room-started', {
        roomId: room.roomId,
        roomName: room.roomName,
        settings: room.settings,
        jitsiDomain: room.jitsiDomain
      });
    });
    
    console.log(`🎥 Jitsi room started: ${room.roomId} by teacher ${req.userId}`);
    
    res.json({ success: true, message: 'Class started', startedAt: room.startedAt });
  } catch (error) {
    console.error('Start class error:', error);
    res.status(500).json({ error: 'Failed to start class' });
  }
});

// Teacher joins the class - enables students to join
// Teacher joins the class - enables students to join
app.post('/api/group-classes/:id/teacher-joined', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const groupClass = await GroupClass.findOne({ 
      _id: req.params.id, 
      teacherId: req.userId 
    });
    
    if (!groupClass) {
      return res.status(404).json({ error: 'Class not found' });
    }
    
    if (groupClass.status !== 'LIVE') {
      return res.status(400).json({ error: 'Class is not live' });
    }
    
    // Mark teacher as in class
    groupClass.teacherInClass = true;
    groupClass.teacherJoinedAt = new Date();
    await groupClass.save();
    
    // Get teacher name
    const teacher = await User.findById(req.userId).select('name');
    
    // Notify all enrolled students that they can now join
    const studentIds = groupClass.isForAllStudents 
      ? (await TeacherStudentLink.find({ teacherId: req.userId, isActive: true })).map(l => l.studentId.toString())
      : groupClass.studentIds.map(id => id.toString());
    
    // Emit to each student's personal room
    studentIds.forEach(studentId => {
      io.to(studentId).emit('class-ready-to-join', {
        classId: groupClass._id.toString(),
        sessionId: groupClass.sessionId,
        title: groupClass.title,
        teacherName: teacher?.name || 'Teacher'
      });
    });
    
    console.log(`👨‍🏫 Teacher joined class: ${groupClass.title} - ${studentIds.length} students notified`);
    
    res.json({ 
      success: true, 
      message: 'Teacher joined, students can now join',
      teacherJoinedAt: groupClass.teacherJoinedAt
    });
  } catch (error) {
    console.error('Teacher joined error:', error);
    res.status(500).json({ error: 'Failed to update class status' });
  }
});

// Teacher leaves the class - ends class for everyone
// Teacher leaves the class - DELETES class for everyone
app.post('/api/group-classes/:id/teacher-left', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const groupClass = await GroupClass.findOne({ 
      _id: req.params.id, 
      teacherId: req.userId 
    });
    
    if (!groupClass) {
      return res.status(404).json({ error: 'Class not found' });
    }
    
    const classId = groupClass._id.toString();
    const sessionId = groupClass.sessionId;
    const classTitle = groupClass.title;
    
    // Get all enrolled students to notify them BEFORE deleting
    const studentIds = groupClass.isForAllStudents 
      ? (await TeacherStudentLink.find({ teacherId: req.userId, isActive: true })).map(l => l.studentId.toString())
      : groupClass.studentIds.map(id => id.toString());
    
    // DELETE the class completely
    await GroupClass.findByIdAndDelete(req.params.id);
    
    // Notify all participants that class has ended and is deleted
    studentIds.forEach(studentId => {
      io.to(studentId).emit('class-ended', {
        classId: classId,
        sessionId: sessionId,
        reason: 'Teacher ended the class',
        deleted: true
      });
    });
    
    // Also broadcast globally
    io.emit('class-ended', {
      classId: classId,
      sessionId: sessionId,
      reason: 'Teacher ended the class',
      deleted: true
    });
    
    console.log(`🗑️ Teacher DELETED class: ${classTitle}`);
    
    res.json({ success: true, message: 'Class ended and deleted' });
  } catch (error) {
    console.error('Teacher left error:', error);
    res.status(500).json({ error: 'Failed to end class' });
  }
});

// Check if student can join (teacher must be in class)
app.get('/api/group-classes/:id/can-join', authRequired, async (req, res) => {
  try {
    const groupClass = await GroupClass.findById(req.params.id)
      .populate('teacherId', 'name avatar');
    
    if (!groupClass) {
      return res.status(404).json({ error: 'Class not found' });
    }
    
    const isTeacher = groupClass.teacherId._id.toString() === req.userId;
    
    // Teachers can always join
    if (isTeacher) {
      return res.json({ 
        success: true, 
        canJoin: true,
        isTeacher: true,
        status: groupClass.status
      });
    }
    
    // Students can only join if class is LIVE AND teacher is in class
    const canJoin = groupClass.status === 'LIVE' && groupClass.teacherInClass === true;
    
    res.json({
      success: true,
      canJoin,
      isTeacher: false,
      status: groupClass.status,
      teacherInClass: groupClass.teacherInClass,
      teacherName: groupClass.teacherId.name,
      message: !canJoin 
        ? (groupClass.status !== 'LIVE' 
            ? 'Class has not started yet' 
            : 'Waiting for teacher to join...')
        : 'You can join now'
    });
  } catch (error) {
    console.error('Can join check error:', error);
    res.status(500).json({ error: 'Failed to check join status' });
  }
});

// End class (Teacher only)
app.post('/api/jitsi/rooms/:roomId/end', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId, teacherId: req.userId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    room.isActive = false;
    room.endedAt = new Date();
    room.updatedAt = new Date();
    await room.save();
    
    // Close all attendance sessions
    await JitsiAttendance.updateMany(
      { roomId: req.params.roomId, 'sessions.leaveTime': null },
      { 
        $set: { 
          'sessions.$.leaveTime': new Date(),
          lastLeave: new Date()
        }
      }
    );
    
    // Recalculate total durations
    const attendances = await JitsiAttendance.find({ roomId: req.params.roomId });
    for (const att of attendances) {
      let totalDuration = 0;
      for (const session of att.sessions) {
        if (session.leaveTime && session.joinTime) {
          const duration = Math.floor((new Date(session.leaveTime) - new Date(session.joinTime)) / 1000);
          session.duration = duration;
          totalDuration += duration;
        }
      }
      att.totalDuration = totalDuration;
      await att.save();
    }
    
    // Broadcast class ended to all participants
    io.emit('jitsi-room-ended', { roomId: room.roomId });
    
    console.log(`🎥 Jitsi room ended: ${room.roomId}`);
    
    res.json({ success: true, message: 'Class ended', endedAt: room.endedAt });
  } catch (error) {
    console.error('End class error:', error);
    res.status(500).json({ error: 'Failed to end class' });
  }
});

// Update room settings (Teacher only) - During live meeting
app.put('/api/jitsi/rooms/:roomId/settings', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { settings } = req.body;
    
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId, teacherId: req.userId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    // Merge settings
    room.settings = { ...room.settings, ...settings };
    room.updatedAt = new Date();
    await room.save();
    
    // Broadcast settings update to all participants in the room
    io.to(`jitsi-${req.params.roomId}`).emit('jitsi-settings-update', {
      roomId: room.roomId,
      settings: room.settings
    });
    
    console.log(`⚙️ Jitsi room settings updated: ${room.roomId}`);
    
    res.json({ success: true, settings: room.settings });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// Mute all students (Teacher only)
app.post('/api/jitsi/rooms/:roomId/mute-all', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId, teacherId: req.userId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    // Update all student enrollments
    await JitsiEnrollment.updateMany(
      { roomId: req.params.roomId, role: 'STUDENT' },
      { mutedByHost: true }
    );
    
    // Broadcast mute command
    io.to(`jitsi-${req.params.roomId}`).emit('jitsi-mute-all', {
      roomId: room.roomId
    });
    
    res.json({ success: true, message: 'All students muted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mute all' });
  }
});

// Mute specific student
app.post('/api/jitsi/rooms/:roomId/mute/:userId', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId, teacherId: req.userId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    await JitsiEnrollment.findOneAndUpdate(
      { roomId: req.params.roomId, userId: req.params.userId },
      { mutedByHost: true }
    );
    
    // Send mute command to specific user
    io.to(req.params.userId).emit('jitsi-mute-user', {
      roomId: room.roomId,
      userId: req.params.userId
    });
    
    res.json({ success: true, message: 'User muted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mute user' });
  }
});

// Disable video for specific student
app.post('/api/jitsi/rooms/:roomId/disable-video/:userId', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId, teacherId: req.userId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    await JitsiEnrollment.findOneAndUpdate(
      { roomId: req.params.roomId, userId: req.params.userId },
      { videoDisabledByHost: true }
    );
    
    io.to(req.params.userId).emit('jitsi-disable-video', {
      roomId: room.roomId,
      userId: req.params.userId
    });
    
    res.json({ success: true, message: 'User video disabled' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to disable video' });
  }
});

// Kick student from room
app.post('/api/jitsi/rooms/:roomId/kick/:userId', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const { reason } = req.body;
    
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId, teacherId: req.userId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    // Update enrollment
    await JitsiEnrollment.findOneAndUpdate(
      { roomId: req.params.roomId, userId: req.params.userId },
      { 
        kicked: true, 
        kickedAt: new Date(), 
        kickedBy: req.userId,
        kickReason: reason || 'Removed by teacher'
      }
    );
    
    // Close attendance session
    const attendance = await JitsiAttendance.findOne({ 
      roomId: req.params.roomId, 
      userId: req.params.userId 
    });
    
    if (attendance) {
      const lastSession = attendance.sessions[attendance.sessions.length - 1];
      if (lastSession && !lastSession.leaveTime) {
        lastSession.leaveTime = new Date();
        lastSession.duration = Math.floor((lastSession.leaveTime - lastSession.joinTime) / 1000);
        attendance.lastLeave = new Date();
        attendance.totalDuration = attendance.sessions.reduce((sum, s) => sum + (s.duration || 0), 0);
        await attendance.save();
      }
    }
    
    // Send kick command to user
    io.to(req.params.userId).emit('jitsi-kicked', {
      roomId: room.roomId,
      userId: req.params.userId,
      reason: reason || 'You have been removed from the class'
    });
    
    console.log(`👢 User ${req.params.userId} kicked from room ${room.roomId}`);
    
    res.json({ success: true, message: 'User kicked' });
  } catch (error) {
    console.error('Kick user error:', error);
    res.status(500).json({ error: 'Failed to kick user' });
  }
});

// Check if user is kicked (for rejoin prevention)
app.get('/api/jitsi/rooms/:roomId/check-access', authRequired, async (req, res) => {
  try {
    const enrollment = await JitsiEnrollment.findOne({
      roomId: req.params.roomId,
      userId: req.userId
    });
    
    if (!enrollment) {
      return res.status(403).json({ error: 'Not enrolled in this class', canJoin: false });
    }
    
    if (enrollment.kicked) {
      return res.status(403).json({ 
        error: 'You have been removed from this class', 
        canJoin: false,
        kickReason: enrollment.kickReason
      });
    }
    
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId });
    
    res.json({ 
      success: true, 
      canJoin: true,
      isActive: room?.isActive || false,
      settings: room?.settings,
      jitsiDomain: room?.jitsiDomain
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to check access' });
  }
});

// Get attendance report for a room
app.get('/api/jitsi/rooms/:roomId/attendance', authRequired, requireRole('TEACHER'), async (req, res) => {
  try {
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId, teacherId: req.userId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    const attendances = await JitsiAttendance.find({ roomId: req.params.roomId })
      .populate('userId', 'name email avatar studentCode')
      .lean();
    
    const report = attendances.map(att => ({
      id: att._id.toString(),
      user: att.userId ? {
        id: att.userId._id.toString(),
        name: att.userId.name,
        email: att.userId.email,
        avatar: att.userId.avatar,
        studentCode: att.userId.studentCode
      } : null,
      role: att.role,
      firstJoin: att.firstJoin,
      lastLeave: att.lastLeave,
      totalMinutes: Math.round(att.totalDuration / 60),
      totalDurationFormatted: formatDuration(att.totalDuration),
      joinCount: att.joinCount,
      sessions: att.sessions.map(s => ({
        joinTime: s.joinTime,
        leaveTime: s.leaveTime,
        durationMinutes: Math.round((s.duration || 0) / 60)
      }))
    }));
    
    res.json({
      success: true,
      roomName: room.roomName,
      startedAt: room.startedAt,
      endedAt: room.endedAt,
      totalParticipants: report.length,
      attendance: report
    });
  } catch (error) {
    console.error('Get attendance error:', error);
    res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});

// Helper function for duration formatting
function formatDuration(seconds) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  } else if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }
  return `${secs}s`;
}

// Get room participants (live)
app.get('/api/jitsi/rooms/:roomId/participants', authRequired, async (req, res) => {
  try {
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    // Get active participants (those with open attendance sessions)
    const activeAttendances = await JitsiAttendance.find({
      roomId: req.params.roomId,
      'sessions.leaveTime': null
    }).populate('userId', 'name avatar role');
    
    const participants = activeAttendances.map(att => ({
      userId: att.userId._id.toString(),
      name: att.userId.name,
      avatar: att.userId.avatar,
      role: att.role,
      joinTime: att.sessions[att.sessions.length - 1]?.joinTime
    }));
    
    res.json({ success: true, participants });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch participants' });
  }
});

// Generate Jitsi JWT token
// Generate Jitsi JWT token - MODIFIED
app.post('/api/jitsi/generate-token', authRequired, async (req, res) => {
  try {
    const { roomId, roomName } = req.body;
    
    if (!roomId || !roomName) {
      return res.status(400).json({ error: 'Room ID and name are required' });
    }
    
    const user = await User.findById(req.userId).select('name avatar');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const isModerator = req.role === 'TEACHER';
    
    if (isModerator) {
      // Auto-create room if it doesn't exist for teachers
      let room = await JitsiRoom.findOne({ roomId, teacherId: req.userId });
      if (!room) {
        room = await JitsiRoom.create({
          roomId,
          roomName,
          teacherId: req.userId,
          isActive: true,
          startedAt: new Date(),
          jitsiDomain: 'meet.jit.si'
        });
        
        // Auto-enroll teacher
        await JitsiEnrollment.findOneAndUpdate(
          { roomId, userId: req.userId },
          { roomId, userId: req.userId, role: 'TEACHER' },
          { upsert: true }
        );
        
        console.log(`🎥 Auto-created Jitsi room: ${roomId}`);
      }
    } else {
      // Students still need enrollment
      const enrollment = await JitsiEnrollment.findOne({
        roomId,
        userId: req.userId,
        kicked: false
      });
      
      if (!enrollment) {
        return res.status(403).json({ error: 'Not enrolled in this room' });
      }
    }
    
    const token = generateJitsiJWT(roomId, user.name, req.userId, isModerator, user.avatar);
    
    if (!token) {
      return res.status(500).json({ error: 'Failed to generate token' });
    }
    
    console.log(`🔑 Generated Jitsi JWT for ${user.name} (${req.role}) in room ${roomId}`);
    
    res.json({
      success: true,
      token,
      user: { name: user.name, avatar: user.avatar, isModerator },
      room: { roomId, roomName }
    });
  } catch (error) {
    console.error('Generate Jitsi token error:', error);
    res.status(500).json({ error: 'Failed to generate token' });
  }
});

// Get Jitsi configuration for room
app.get('/api/jitsi/rooms/:roomId/config', authRequired, async (req, res) => {
  try {
    const room = await JitsiRoom.findOne({ roomId: req.params.roomId });
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    // Check access
    const isModerator = req.role === 'TEACHER' && room.teacherId.toString() === req.userId;
    
    if (!isModerator) {
      const enrollment = await JitsiEnrollment.findOne({
        roomId: req.params.roomId,
        userId: req.userId,
        kicked: false
      });
      
      if (!enrollment) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    
    res.json({
      success: true,
      config: {
        roomId: room.roomId,
        roomName: room.roomName,
        jitsiDomain: room.jitsiDomain || 'meet.jit.si',
        settings: room.settings,
        isActive: room.isActive,
        isModerator,
        appId: JITSI_APP_ID // Send app ID to client
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get room config' });
  }
});

// ========================================
// ========= ENHANCED AUTH APIs =========
// ========================================

// ========================================
// ========= UPDATED AUTH APIs ===========
// ========= (Firebase Verified) ==========
// ========================================

// NOTE: All email and SMS OTPs are now handled by Firebase on the client side.
// Backend just accepts "FIREBASE_VERIFIED" as proof of verification.
// No Twilio or Gmail SMTP required!

// ========= GOOGLE OAUTH =========

// Google Sign-In - Initial verification
app.post('/api/auth/google', async (req, res) => {
  try {
    const { idToken } = req.body;
    
    if (!idToken) {
      return res.status(400).json({ error: 'ID token required' });
    }
    
    const payload = await verifyGoogleToken(idToken);
    if (!payload) {
      return res.status(401).json({ error: 'Invalid Google token' });
    }
    
    const { sub: googleId, email, name, picture } = payload;
    
    // Check if user already exists with this Google ID
    let user = await User.findOne({ googleId });
    
    if (user) {
      // Existing Google user - check 2FA
      const twoFA = await TwoFactorAuth.findOne({ userId: user._id, isEnabled: true });
      
      if (twoFA) {
        const tempToken = jwt.sign({ userId: user._id, pending2FA: true }, JWT_SECRET, { expiresIn: '10m' });
        return res.json({
          success: true,
          requires2FA: true,
          tempToken,
          user: { name: user.name }
        });
      }
      
      const token = jwt.sign(
        { userId: user._id, role: user.role, name: user.name },
        JWT_SECRET,
        { expiresIn: '30d' }
      );
      
      user.lastLogin = new Date();
      user.isOnline = true;
      await user.save();
      
      return res.json({
        success: true,
        isNewUser: false,
        token,
        user: {
          id: user._id.toString(),
          name: user.name,
          email: user.email,
          role: user.role,
          mobile: user.mobile,
          studentCode: user.studentCode,
          avatar: user.avatar || picture
        }
      });
    }
    
    // Check if email exists with password-based account
    const existingEmailUser = await User.findOne({ email: email.toLowerCase() });
    if (existingEmailUser && !existingEmailUser.googleId) {
      return res.status(409).json({ 
        error: 'An account with this email already exists. Please login with your password.',
        existingAccount: true
      });
    }
    
    // New Google user - create pending registration
    const pendingToken = crypto.randomBytes(32).toString('hex');
    
    await GooglePendingUser.findOneAndUpdate(
      { googleId },
      {
        googleId,
        email,
        name,
        avatar: picture,
        pendingToken,
        expiresAt: new Date(Date.now() + 30 * 60 * 1000)
      },
      { upsert: true, new: true }
    );
    
    res.json({
      success: true,
      isNewUser: true,
      pendingToken,
      googleUser: { email, name, avatar: picture }
    });
    
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Complete Google registration (after collecting role + mobile)
// Firebase will send the SMS OTP on client side
app.post('/api/auth/google/complete', async (req, res) => {
  try {
    const { pendingToken, role, mobile } = req.body;
    
    if (!pendingToken || !role || !mobile) {
      return res.status(400).json({ error: 'Pending token, role, and mobile are required' });
    }
    
    if (!['STUDENT', 'TEACHER'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    
    // Find pending Google user
    const pending = await GooglePendingUser.findOne({ pendingToken });
    if (!pending) {
      return res.status(400).json({ error: 'Invalid or expired registration. Please try again.' });
    }
    
    // Store mobile temporarily for verification step
    pending.mobile = mobile;
    pending.role = role;
    await pending.save();
    
    // Tell client to send OTP via Firebase (Google)
    res.json({
      success: true,
      message: 'Please verify your mobile number',
      requiresOTP: true,
      pendingToken
    });
    
  } catch (error) {
    console.error('Google complete error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Verify OTP and finalize Google registration
// Accepts FIREBASE_VERIFIED - Firebase handled the OTP on client side
app.post('/api/auth/google/verify-otp', async (req, res) => {
  try {
    const { pendingToken, mobile, otp, role } = req.body;
    
    if (!pendingToken || !mobile || !otp || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Find pending Google user
    const pending = await GooglePendingUser.findOne({ pendingToken });
    if (!pending) {
      return res.status(400).json({ error: 'Invalid or expired registration' });
    }
    
    // Accept FIREBASE_VERIFIED - Firebase Phone Auth verified the OTP on client
    if (otp !== 'FIREBASE_VERIFIED') {
      return res.status(400).json({ error: 'Phone verification required via Google Firebase' });
    }
    
    // Create user
    let studentCode = null;
    if (role === 'STUDENT') {
      do {
        studentCode = generateStudentCode();
      } while (await User.exists({ studentCode }));
    }
    
    const user = await User.create({
      name: pending.name,
      email: pending.email.toLowerCase(),
      mobile,
      passwordHash: await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10),
      role,
      studentCode,
      avatar: pending.avatar,
      googleId: pending.googleId,
      isGoogleUser: true,
      isEmailVerified: true,
      isMobileVerified: true
    });
    
    // Cleanup
    await GooglePendingUser.deleteOne({ pendingToken });
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    console.log(`✅ New Google user registered: ${user.email} as ${role}`);
    
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
    console.error('Google verify OTP error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ========= MANUAL SIGNUP WITH FIREBASE VERIFICATION =========

// Send OTP for manual signup - Now just tells client to use Firebase
app.post('/api/auth/signup/send-otp', async (req, res) => {
  try {
    const { email, mobile, role } = req.body;
    
    if (!email || !role) {
      return res.status(400).json({ error: 'Email and role are required' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }
    
    // Tell client to send OTPs via Firebase (Google handles both email link and SMS)
    res.json({
      success: true,
      message: 'Please verify using Firebase',
      requiresEmailOTP: true,
      requiresSmsOTP: role === 'TEACHER' && !!mobile
    });
    
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Verify OTP and complete signup
// Accepts FIREBASE_VERIFIED for both email and SMS
// Verify OTP and complete signup
// Email OTP verified by backend, SMS OTP verified by Firebase (Google)
app.post('/api/auth/signup/verify', async (req, res) => {
  try {
    const { name, email, mobile, password, role, emailOtp, smsOtp } = req.body;
    
    if (!name || !email || !password || !role || !emailOtp) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }
    
    // Verify Email OTP was verified in database
    const emailOtpRecord = await OTP.findOne({ 
      email: email.toLowerCase(), 
      purpose: 'SIGNUP', 
      type: 'EMAIL',
      verified: true 
    });
    
    if (!emailOtpRecord) {
      // If not pre-verified, verify now with the provided OTP
      const otpRecord = await OTP.findOne({ 
        email: email.toLowerCase(), 
        purpose: 'SIGNUP', 
        type: 'EMAIL' 
      });
      
      if (!otpRecord) {
        return res.status(400).json({ error: 'Please request an email OTP first' });
      }
      
      const isValidOtp = await bcrypt.compare(emailOtp, otpRecord.otp);
      if (!isValidOtp) {
        otpRecord.attempts += 1;
        await otpRecord.save();
        return res.status(400).json({ error: 'Invalid email OTP' });
      }
    }
    
    // For teachers, verify SMS was done via Firebase
    if (role === 'TEACHER' && mobile) {
      if (smsOtp !== 'FIREBASE_VERIFIED') {
        return res.status(400).json({ error: 'Phone verification required via Firebase' });
      }
    }
    
    // Create user
    let studentCode = null;
    if (role === 'STUDENT') {
      do {
        studentCode = generateStudentCode();
      } while (await User.exists({ studentCode }));
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    const user = await User.create({
      name,
      email: email.toLowerCase(),
      mobile,
      passwordHash,
      role,
      studentCode,
      isEmailVerified: true,
      isMobileVerified: role === 'TEACHER' && !!mobile
    });
    
    // Cleanup OTPs
    await OTP.deleteMany({ email: email.toLowerCase(), purpose: 'SIGNUP' });
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    console.log(`✅ New user registered: ${email} as ${role}`);
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        mobile: user.mobile,
        studentCode: user.studentCode
      }
    });
    
  } catch (error) {
    console.error('Signup verify error:', error);
    if (error.code === 11000) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ========= RESEND OTP (Now just acknowledges - Firebase handles on client) =========
app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { email, mobile, type, purpose } = req.body;
    
    // Firebase handles OTP sending on client side
    // This endpoint just acknowledges the request
    res.json({ 
      success: true, 
      message: 'Please resend OTP via Firebase on your device' 
    });
    
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// ========= TWO-FACTOR AUTHENTICATION =========
// (These remain the same - 2FA uses Google Authenticator app, not OTP)

// Setup 2FA - Generate secret
app.post('/api/auth/2fa/setup', authRequired, async (req, res) => {
  try {
    console.log('🔐 2FA Setup requested for userId:', req.userId);
    
    // Convert string to ObjectId properly
    const userId = new mongoose.Types.ObjectId(req.userId);
    
    const existing = await TwoFactorAuth.findOne({ userId });
    if (existing && existing.isEnabled) {
      return res.status(400).json({ error: '2FA is already enabled' });
    }
    
    const user = await User.findById(userId);
    console.log('🔐 User lookup result:', user ? 'Found' : 'Not found', 'for ID:', req.userId);
    
    if (!user) {
      // Debug: Check if user exists with different query
      const allUsers = await User.find({}).select('_id email').limit(5);
      console.log('🔐 Sample users in DB:', allUsers.map(u => u._id.toString()));
      return res.status(404).json({ error: 'User not found' });
    }
    
    const secret = speakeasy.generateSecret({
      name: `TuitionManager (${user.email})`,
      issuer: 'TuitionManager'
    });
    
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    
    await TwoFactorAuth.findOneAndUpdate(
      { userId },
      {
        userId,
        secret: secret.base32,
        isEnabled: false,
        backupCodes: generateBackupCodes()
      },
      { upsert: true, new: true }
    );
    
    res.json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeUrl,
      message: 'Scan the QR code with Google Authenticator, then verify with a code'
    });
    
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({ error: 'Failed to setup 2FA' });
  }
});

// Verify and enable 2FA
app.post('/api/auth/2fa/verify', authRequired, async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Verification code required' });
    }
    
    const twoFA = await TwoFactorAuth.findOne({ userId: req.userId });
    if (!twoFA) {
      return res.status(400).json({ error: 'Please setup 2FA first' });
    }
    
    const isValid = speakeasy.totp.verify({
      secret: twoFA.secret,
      encoding: 'base32',
      token: code,
      window: 2
    });
    
    if (!isValid) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }
    
    twoFA.isEnabled = true;
    twoFA.enabledAt = new Date();
    await twoFA.save();
    
    await User.findByIdAndUpdate(req.userId, { twoFactorEnabled: true });
    
    res.json({
      success: true,
      message: '2FA enabled successfully',
      backupCodes: twoFA.backupCodes.map(b => b.code)
    });
    
  } catch (error) {
    console.error('2FA verify error:', error);
    res.status(500).json({ error: 'Failed to verify 2FA' });
  }
});

// Disable 2FA
app.post('/api/auth/2fa/disable', authRequired, async (req, res) => {
  try {
    const { code, password } = req.body;
    
    if (!code || !password) {
      return res.status(400).json({ error: 'Code and password required' });
    }
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    
    const twoFA = await TwoFactorAuth.findOne({ userId: req.userId });
    if (!twoFA || !twoFA.isEnabled) {
      return res.status(400).json({ error: '2FA is not enabled' });
    }
    
    const isValid = speakeasy.totp.verify({
      secret: twoFA.secret,
      encoding: 'base32',
      token: code,
      window: 2
    });
    
    if (!isValid) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }
    
    await TwoFactorAuth.deleteOne({ userId: req.userId });
    await User.findByIdAndUpdate(req.userId, { twoFactorEnabled: false });
    
    res.json({ success: true, message: '2FA disabled successfully' });
    
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

// Get 2FA status
app.get('/api/auth/2fa/status', authRequired, async (req, res) => {
  try {
    const twoFA = await TwoFactorAuth.findOne({ userId: req.userId });
    
    res.json({
      success: true,
      isEnabled: twoFA?.isEnabled || false,
      enabledAt: twoFA?.enabledAt
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to get 2FA status' });
  }
});

// Verify 2FA during login
app.post('/api/auth/2fa/login-verify', async (req, res) => {
  try {
    const { tempToken, code, useBackupCode } = req.body;
    
    if (!tempToken || !code) {
      return res.status(400).json({ error: 'Token and code required' });
    }
    
    let decoded;
    try {
      decoded = jwt.verify(tempToken, JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Session expired. Please login again.' });
    }
    
    if (!decoded.pending2FA) {
      return res.status(400).json({ error: 'Invalid token' });
    }
    
    const twoFA = await TwoFactorAuth.findOne({ userId: decoded.userId });
    if (!twoFA) {
      return res.status(400).json({ error: '2FA not found' });
    }
    
    let isValid = false;
    
    if (useBackupCode) {
      const backupCode = twoFA.backupCodes.find(b => b.code === code && !b.used);
      if (backupCode) {
        backupCode.used = true;
        await twoFA.save();
        isValid = true;
      }
    } else {
      isValid = speakeasy.totp.verify({
        secret: twoFA.secret,
        encoding: 'base32',
        token: code,
        window: 2
      });
    }
    
    if (!isValid) {
      return res.status(400).json({ error: 'Invalid code' });
    }
    
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const token = jwt.sign(
      { userId: user._id, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    user.lastLogin = new Date();
    user.isOnline = true;
    await user.save();
    
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
        avatar: user.avatar
      }
    });
    
  } catch (error) {
    console.error('2FA login verify error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ========= FORGOT PASSWORD (Firebase Verified) =========

// Request password reset - Send email OTP or tell client to use Firebase for SMS
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email, mobile } = req.body;
    
    if (!email && !mobile) {
      return res.status(400).json({ error: 'Email or mobile required' });
    }
    
    // Find user
    const query = email ? { email: email.toLowerCase() } : { mobile };
    const user = await User.findOne(query);
    
    if (!user) {
      // Don't reveal if user exists - but still return success
      return res.json({ 
        success: true, 
        message: 'If an account exists, you will receive an OTP',
        otpType: email ? 'EMAIL' : 'SMS'
      });
    }
    
    if (email) {
      // Send email OTP via Resend
      const otp = generateOTP();
      const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
      
      const emailResult = await sendEmailOTP(email, otp, 'RESET_PASSWORD');
      if (!emailResult.success) {
        return res.status(500).json({ error: 'Failed to send OTP' });
      }
      
      await OTP.findOneAndUpdate(
        { email: email.toLowerCase(), purpose: 'RESET_PASSWORD', type: 'EMAIL' },
        {
          userId: user._id,
          email: email.toLowerCase(),
          otp: await bcrypt.hash(otp, 10),
          type: 'EMAIL',
          purpose: 'RESET_PASSWORD',
          attempts: 0,
          expiresAt: otpExpiry
        },
        { upsert: true }
      );
    }
    // For mobile, Firebase will handle OTP on client side
    
    res.json({ 
      success: true, 
      message: email ? 'OTP sent to email' : 'Please verify via Firebase',
      otpType: email ? 'EMAIL' : 'SMS'
    });
    
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Verify OTP and get reset token
// Accepts FIREBASE_VERIFIED - Firebase handled verification on client
// Verify OTP and get reset token
// Email OTP verified by backend, Phone OTP verified by Firebase
app.post('/api/auth/forgot-password/verify', async (req, res) => {
  try {
    const { email, mobile, otp } = req.body;
    
    if ((!email && !mobile) || !otp) {
      return res.status(400).json({ error: 'OTP and email/mobile required' });
    }
    
    // Find user
    const query = email ? { email: email.toLowerCase() } : { mobile };
    const user = await User.findOne(query);
    
    if (!user) {
      return res.status(400).json({ error: 'Account not found' });
    }
    
    if (mobile) {
      // Phone OTP - Accept FIREBASE_VERIFIED
      if (otp !== 'FIREBASE_VERIFIED') {
        return res.status(400).json({ error: 'Phone verification required via Firebase' });
      }
    } else {
      // Email OTP - Verify with backend
      const otpRecord = await OTP.findOne({ 
        email: email.toLowerCase(), 
        purpose: 'RESET_PASSWORD', 
        type: 'EMAIL' 
      });
      
      if (!otpRecord) {
        return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
      }
      
      if (otpRecord.attempts >= 5) {
        return res.status(429).json({ error: 'Too many attempts. Please request a new OTP.' });
      }
      
      const isValid = await bcrypt.compare(otp, otpRecord.otp);
      if (!isValid) {
        otpRecord.attempts += 1;
        await otpRecord.save();
        return res.status(400).json({ error: 'Invalid OTP' });
      }
      
      // Delete used OTP
      await OTP.deleteOne({ _id: otpRecord._id });
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    await PasswordReset.create({
      userId: user._id,
      token: resetToken,
      otpVerified: true,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
    });
    
    res.json({
      success: true,
      resetToken,
      message: 'Verified. You can now reset your password.'
    });
    
  } catch (error) {
    console.error('Verify forgot password error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    
    if (!resetToken || !newPassword) {
      return res.status(400).json({ error: 'Reset token and new password required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const resetRecord = await PasswordReset.findOne({ token: resetToken, otpVerified: true });
    
    if (!resetRecord) {
      return res.status(400).json({ error: 'Invalid or expired reset link' });
    }
    
    const passwordHash = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(resetRecord.userId, { passwordHash });
    
    await PasswordReset.deleteOne({ _id: resetRecord._id });
    
    console.log(`✅ Password reset for user: ${resetRecord.userId}`);
    
    res.json({ success: true, message: 'Password reset successfully' });
    
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ========= ENHANCED LOGIN WITH 2FA =========
app.post('/api/auth/login/enhanced', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const twoFA = await TwoFactorAuth.findOne({ userId: user._id, isEnabled: true });
    
    if (twoFA) {
      const tempToken = jwt.sign(
        { userId: user._id, pending2FA: true },
        JWT_SECRET,
        { expiresIn: '10m' }
      );
      
      return res.json({
        success: true,
        requires2FA: true,
        tempToken,
        user: { name: user.name }
      });
    }
    
    const token = jwt.sign(
      { userId: user._id, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    user.lastLogin = new Date();
    user.isOnline = true;
    await user.save();
    
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
        avatar: user.avatar
      }
    });
    
  } catch (error) {
    console.error('Enhanced login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ========= EMAIL OTP ENDPOINTS (Backend sends email via Resend) =========

// Send Email OTP
app.post('/api/auth/email/send-otp', async (req, res) => {
  try {
    const { email, purpose } = req.body;
    
    if (!email || !purpose) {
      return res.status(400).json({ error: 'Email and purpose required' });
    }
    
    if (!['SIGNUP', 'RESET_PASSWORD', 'LOGIN'].includes(purpose)) {
      return res.status(400).json({ error: 'Invalid purpose' });
    }
    
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    
    // Send email via Resend
    const emailResult = await sendEmailOTP(email, otp, purpose);
    if (!emailResult.success) {
      return res.status(500).json({ error: 'Failed to send email: ' + emailResult.error });
    }
    
    // Store OTP in database
    await OTP.findOneAndUpdate(
      { email: email.toLowerCase(), purpose, type: 'EMAIL' },
      {
        email: email.toLowerCase(),
        otp: await bcrypt.hash(otp, 10),
        type: 'EMAIL',
        purpose,
        verified: false,
        attempts: 0,
        expiresAt: otpExpiry
      },
      { upsert: true }
    );
    
    res.json({ success: true, message: 'OTP sent to email' });
    
  } catch (error) {
    console.error('Send email OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify Email OTP
app.post('/api/auth/email/verify-otp', async (req, res) => {
  try {
    const { email, otp, purpose } = req.body;
    
    if (!email || !otp || !purpose) {
      return res.status(400).json({ error: 'Email, OTP and purpose required', verified: false });
    }
    
    const otpRecord = await OTP.findOne({ 
      email: email.toLowerCase(), 
      purpose, 
      type: 'EMAIL' 
    });
    
    if (!otpRecord) {
      return res.status(400).json({ error: 'OTP expired or not found', verified: false });
    }
    
    // Check expiry
    if (new Date() > otpRecord.expiresAt) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({ error: 'OTP expired', verified: false });
    }
    
    // Check attempts
    if (otpRecord.attempts >= 5) {
      return res.status(429).json({ error: 'Too many attempts. Please request a new OTP.', verified: false });
    }
    
    // Verify OTP
    const isValid = await bcrypt.compare(otp, otpRecord.otp);
    
    if (!isValid) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      return res.status(400).json({ error: 'Invalid OTP', verified: false });
    }
    
    // Mark as verified
    otpRecord.verified = true;
    await otpRecord.save();
    
    res.json({ success: true, verified: true, message: 'Email verified' });
    
  } catch (error) {
    console.error('Verify email OTP error:', error);
    res.status(500).json({ error: 'Verification failed', verified: false });
  }
});

// ========= STUDENT CODE ENDPOINT =========
app.get('/api/student/code', authRequired, async (req, res) => {
  try {
    console.log('📋 Student code requested for userId:', req.userId);
    
    // Convert string to ObjectId
    const userId = new mongoose.Types.ObjectId(req.userId);
    
    const user = await User.findById(userId).select('studentCode role');
    
    if (!user) {
      console.log('📋 User not found for ID:', req.userId);
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.role !== 'STUDENT') {
      return res.status(400).json({ error: 'Only students have student codes' });
    }
    
    if (!user.studentCode) {
      // Generate one if missing
      let studentCode;
      do {
        studentCode = generateStudentCode();
      } while (await User.exists({ studentCode }));
      
      user.studentCode = studentCode;
      await user.save();
      console.log('📋 Generated new student code:', studentCode);
    }
    
    res.json({ 
      success: true, 
      code: user.studentCode 
    });
    
  } catch (error) {
    console.error('Get student code error:', error);
    res.status(500).json({ error: 'Failed to get student code' });
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
