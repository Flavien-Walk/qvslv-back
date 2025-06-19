// server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const http = require("http");
const socketIo = require("socket.io");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: [
      'http://localhost:3000',
      'http://localhost:8081',
      'http://localhost:19006',
      'https://qvslv-front.onrender.com',
      'https://www.qvslv.com',
    ],
    methods: ["GET", "POST"]
  }
});

app.set('trust proxy', 1);
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "votre_jwt_secret_ultra_securise_changez_moi";

// Sécurité : vérifie que MONGO_URI est bien défini
if (!MONGO_URI) {
  console.error("❌ Erreur : MONGO_URI n'est pas défini dans le fichier .env");
  process.exit(1);
}

// Middleware de sécurité
app.use(helmet());
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:8081',
  'http://localhost:19006',
  'https://qvslv-front.onrender.com',
  'https://www.qvslv.com',
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`❌ CORS refusé pour : ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  next();
});

app.use(express.json({ limit: '10mb' }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Trop de tentatives de connexion. Réessayez dans 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/auth', authLimiter);
app.use('/api/', generalLimiter);

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Le nom d\'utilisateur est requis'],
    unique: true, // Crée déjà un index unique
    trim: true,
    minlength: [3, 'Le nom d\'utilisateur doit contenir au moins 3 caractères'],
    maxlength: [30, 'Le nom d\'utilisateur ne peut pas dépasser 30 caractères'],
    match: [/^[a-zA-Z0-9_-]+$/, 'Le nom d\'utilisateur ne peut contenir que des lettres, chiffres, _ et -']
  },
  email: {
    type: String,
    required: [true, 'L\'email est requis'],
    unique: true, // Crée aussi un index unique
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Format d\'email invalide']
  },
  password: {
    type: String,
    required: [true, 'Le mot de passe est requis'],
    minlength: [8, 'Le mot de passe doit contenir au moins 8 caractères']
  },
  role: {
    type: String,
    enum: ['member', 'moderator', 'expert', 'admin'],
    default: 'member'
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verified: {
    type: Boolean,
    default: false
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  verificationToken: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: Date,
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date
}, {
  timestamps: true
});


// Schéma des salons de chat
const chatRoomSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  description: String,
  category: String,
  isPrivate: {
    type: Boolean,
    default: false
  },
  verified: {
    type: Boolean,
    default: false
  },
  members: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  moderators: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});


// Schéma des messages
const messageSchema = new mongoose.Schema({
  content: {
    type: String,
    required: true,
    maxlength: 2000
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  chatRoom: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ChatRoom',
    required: true
  },
  replyTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  mentions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  reactions: [{
    emoji: String,
    users: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }]
  }],
  attachments: [{
    type: {
      type: String,
      enum: ['image', 'document', 'audio']
    },
    url: String,
    name: String,
    size: Number
  }],
  edited: {
    type: Boolean,
    default: false
  },
  editedAt: Date,
  isSystem: {
    type: Boolean,
    default: false
  },
  deleted: {
    type: Boolean,
    default: false
  },
  deletedAt: Date
}, {
  timestamps: true
});

// Schéma pour les activités utilisateur (existant)
const activitySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['upload', 'download', 'contribution', 'login', 'chat_message'],
    required: true
  },
  category: {
    type: String,
    default: null
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index pour améliorer les performances
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
activitySchema.index({ userId: 1, timestamp: -1 });
activitySchema.index({ userId: 1, type: 1 });
messageSchema.index({ chatRoom: 1, createdAt: -1 });
messageSchema.index({ author: 1 });


// Middleware pour hasher le mot de passe (existant)
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Méthodes utilisateur (existantes)
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      userId: this._id, 
      username: this.username,
      email: this.email,
      role: this.role
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
};

userSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

userSchema.methods.incLoginAttempts = function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5 && !this.isLocked()) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 };
  }
  
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

const User = mongoose.model('User', userSchema);
const Activity = mongoose.model('Activity', activitySchema);
const ChatRoom = mongoose.model('ChatRoom', chatRoomSchema);
const Message = mongoose.model('Message', messageSchema);

// Middleware d'authentification (existant)
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token d\'accès requis' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ error: 'Token invalide' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Token invalide ou expiré' });
  }
};

// Fonction pour enregistrer une activité (existante)
const logActivity = async (userId, type, category = null, details = {}) => {
  try {
    const activity = new Activity({
      userId,
      type,
      category,
      details
    });
    await activity.save();
  } catch (error) {
    console.error('Erreur lors de l\'enregistrement de l\'activité:', error);
  }
};

// Validation du mot de passe (existante)
const validatePassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  const errors = [];
  
  if (password.length < minLength) {
    errors.push(`Le mot de passe doit contenir au moins ${minLength} caractères`);
  }
  if (!hasUpperCase) {
    errors.push('Le mot de passe doit contenir au moins une majuscule');
  }
  if (!hasLowerCase) {
    errors.push('Le mot de passe doit contenir au moins une minuscule');
  }
  if (!hasNumbers) {
    errors.push('Le mot de passe doit contenir au moins un chiffre');
  }
  if (!hasSpecialChar) {
    errors.push('Le mot de passe doit contenir au moins un caractère spécial');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

// Routes d'authentification (existantes - je garde les principales)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({
        error: 'Tous les champs sont requis'
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        error: 'Les mots de passe ne correspondent pas'
      });
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        error: 'Mot de passe invalide',
        details: passwordValidation.errors
      });
    }

    const existingUserByEmail = await User.findOne({ email: email.toLowerCase() });
    if (existingUserByEmail) {
      return res.status(409).json({
        error: 'Un compte avec cet email existe déjà'
      });
    }

    const existingUserByUsername = await User.findOne({ username });
    if (existingUserByUsername) {
      return res.status(409).json({
        error: 'Ce nom d\'utilisateur est déjà pris'
      });
    }

    const user = new User({
      username,
      email: email.toLowerCase(),
      password,
      verificationToken: jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' })
    });

    await user.save();
    await logActivity(user._id, 'contribution', 'inscription', {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const token = user.generateAuthToken();

    res.status(201).json({
      message: 'Compte créé avec succès',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
        verified: user.verified,
        createdAt: user.createdAt
      },
      token
    });

  } catch (error) {
    console.error('Erreur lors de l\'inscription:', error);

    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(409).json({
        error: `Ce ${field === 'email' ? 'email' : 'nom d\'utilisateur'} est déjà utilisé`
      });
    }

    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        error: 'Données invalides',
        details: messages
      });
    }

    res.status(500).json({
      error: 'Erreur interne du serveur'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email et mot de passe requis'
      });
    }

    const user = await User.findOne({ 
      $or: [
        { email: email.toLowerCase() },
        { username: email }
      ]
    });

    if (!user) {
      return res.status(401).json({
        error: 'Identifiants invalides'
      });
    }

    if (user.isLocked()) {
      return res.status(423).json({
        error: 'Compte temporairement verrouillé en raison de trop nombreuses tentatives de connexion'
      });
    }

    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      await user.incLoginAttempts();
      return res.status(401).json({
        error: 'Identifiants invalides'
      });
    }

    if (user.loginAttempts > 0) {
      await user.resetLoginAttempts();
    }

    user.lastLogin = new Date();
    user.isOnline = true;
    await user.save();

    await logActivity(user._id, 'login', null, {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const token = user.generateAuthToken();

    res.json({
      message: 'Connexion réussie',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
        verified: user.verified,
        lastLogin: user.lastLogin
      },
      token
    });

  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({
      error: 'Erreur interne du serveur'
    });
  }
});

// NOUVELLES ROUTES POUR LE CHAT

// Récupérer tous les salons de chat
app.get('/api/chat/rooms', authenticateToken, async (req, res) => {
  try {
    const rooms = await ChatRoom.find({ deleted: { $ne: true } })
      .populate('createdBy', 'username')
      .populate('members', 'username isOnline')
      .sort({ createdAt: -1 });

    const roomsWithStats = await Promise.all(rooms.map(async (room) => {
      const memberCount = room.members ? room.members.length : 0;
      const onlineCount = room.members ? room.members.filter(m => m.isOnline).length : 0;
      
      // Récupérer le dernier message
      const lastMessage = await Message.findOne({ 
        chatRoom: room._id, 
        deleted: { $ne: true } 
      })
        .populate('author', 'username')
        .sort({ createdAt: -1 });

      return {
        id: room._id,
        name: room.name,
        description: room.description,
        category: room.category,
        isPrivate: room.isPrivate,
        verified: room.verified,
        memberCount,
        onlineCount,
        lastMessage: lastMessage ? {
          author: lastMessage.author.username,
          content: lastMessage.content,
          timestamp: lastMessage.createdAt
        } : null
      };
    }));

    res.json({ rooms: roomsWithStats });
  } catch (error) {
    console.error('Erreur lors de la récupération des salons:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// Récupérer les messages d'un salon
app.get('/api/chat/rooms/:roomId/messages', authenticateToken, async (req, res) => {
  try {
    const { roomId } = req.params;
    const { limit = 50, page = 1 } = req.query;

    const room = await ChatRoom.findById(roomId);
    if (!room) {
      return res.status(404).json({ error: 'Salon non trouvé' });
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const messages = await Message.find({ 
      chatRoom: roomId, 
      deleted: { $ne: true } 
    })
      .populate('author', 'username role verified isVerified')
      .populate('replyTo', 'content author')
      .populate('mentions', 'username')
      .populate('reactions.users', 'username')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const formattedMessages = messages.reverse().map(message => ({
      id: message._id,
      userId: message.author._id,
      username: message.author.username,
      role: message.author.role,
      verified: message.author.verified || message.author.isVerified,
      content: message.content,
      timestamp: message.createdAt,
      edited: message.edited,
      editedAt: message.editedAt,
      isSystem: message.isSystem,
      replyTo: message.replyTo,
      mentions: message.mentions.map(m => m.username),
      reactions: message.reactions.map(r => ({
        emoji: r.emoji,
        count: r.users.length,
        users: r.users.map(u => u._id.toString())
      })),
      attachments: message.attachments || []
    }));

    res.json({ messages: formattedMessages });
  } catch (error) {
    console.error('Erreur lors de la récupération des messages:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// Envoyer un message
app.post('/api/chat/rooms/:roomId/messages', authenticateToken, async (req, res) => {
  try {
    const { roomId } = req.params;
    const { content, replyTo, mentions } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Le contenu du message est requis' });
    }

    if (content.length > 2000) {
      return res.status(400).json({ error: 'Le message ne peut pas dépasser 2000 caractères' });
    }

    const room = await ChatRoom.findById(roomId);
    if (!room) {
      return res.status(404).json({ error: 'Salon non trouvé' });
    }

    const message = new Message({
      content: content.trim(),
      author: req.user._id,
      chatRoom: roomId,
      replyTo: replyTo || null,
      mentions: mentions || []
    });

    await message.save();
    await message.populate('author', 'username role verified isVerified');

    // Enregistrer l'activité
    await logActivity(req.user._id, 'chat_message', room.name, {
      messageId: message._id,
      roomId
    });

    const formattedMessage = {
      id: message._id,
      userId: message.author._id,
      username: message.author.username,
      role: message.author.role,
      verified: message.author.verified || message.author.isVerified,
      content: message.content,
      timestamp: message.createdAt,
      edited: false,
      isSystem: false,
      reactions: [],
      attachments: []
    };

    // Émettre le message via Socket.IO
    io.to(`room_${roomId}`).emit('new_message', formattedMessage);

    res.status(201).json({ 
      message: 'Message envoyé avec succès',
      data: formattedMessage
    });
  } catch (error) {
    console.error('Erreur lors de l\'envoi du message:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// Modifier un message
app.put('/api/chat/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { content } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Le contenu du message est requis' });
    }

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message non trouvé' });
    }

    if (message.author.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Vous ne pouvez modifier que vos propres messages' });
    }

    message.content = content.trim();
    message.edited = true;
    message.editedAt = new Date();
    await message.save();

    // Émettre la modification via Socket.IO
    io.to(`room_${message.chatRoom}`).emit('message_edited', {
      messageId: message._id,
      content: message.content,
      edited: true,
      editedAt: message.editedAt
    });

    res.json({ message: 'Message modifié avec succès' });
  } catch (error) {
    console.error('Erreur lors de la modification du message:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// Supprimer un message
app.delete('/api/chat/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message non trouvé' });
    }

    // Vérifier les permissions
    const canDelete = message.author.toString() === req.user._id.toString() || 
                     req.user.role === 'admin' || 
                     req.user.role === 'moderator';

    if (!canDelete) {
      return res.status(403).json({ error: 'Permission insuffisante' });
    }

    message.deleted = true;
    message.deletedAt = new Date();
    await message.save();

    // Émettre la suppression via Socket.IO
    io.to(`room_${message.chatRoom}`).emit('message_deleted', {
      messageId: message._id
    });

    res.json({ message: 'Message supprimé avec succès' });
  } catch (error) {
    console.error('Erreur lors de la suppression du message:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// Ajouter/Retirer une réaction
app.post('/api/chat/messages/:messageId/reactions', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { emoji } = req.body;

    if (!emoji) {
      return res.status(400).json({ error: 'Emoji requis' });
    }

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message non trouvé' });
    }

    const existingReaction = message.reactions.find(r => r.emoji === emoji);

    if (existingReaction) {
      const userIndex = existingReaction.users.indexOf(req.user._id);
      if (userIndex > -1) {
        // Retirer la réaction
        existingReaction.users.splice(userIndex, 1);
        if (existingReaction.users.length === 0) {
          message.reactions = message.reactions.filter(r => r.emoji !== emoji);
        }
      } else {
        // Ajouter l'utilisateur à la réaction
        existingReaction.users.push(req.user._id);
      }
    } else {
      // Créer une nouvelle réaction
      message.reactions.push({
        emoji,
        users: [req.user._id]
      });
    }

    await message.save();

    const reactionData = message.reactions.map(r => ({
      emoji: r.emoji,
      count: r.users.length,
      users: r.users.map(u => u.toString())
    }));

    // Émettre la réaction via Socket.IO
    io.to(`room_${message.chatRoom}`).emit('message_reaction', {
      messageId: message._id,
      reactions: reactionData
    });

    res.json({ 
      message: 'Réaction mise à jour',
      reactions: reactionData
    });
  } catch (error) {
    console.error('Erreur lors de la gestion de la réaction:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// Récupérer les utilisateurs en ligne d'un salon
app.get('/api/chat/rooms/:roomId/users', authenticateToken, async (req, res) => {
  try {
    const { roomId } = req.params;

    const room = await ChatRoom.findById(roomId).populate('members', 'username role verified isVerified isOnline lastSeen');
    if (!room) {
      return res.status(404).json({ error: 'Salon non trouvé' });
    }

    const users = room.members.map(user => ({
      id: user._id,
      username: user.username,
      role: user.role,
      verified: user.verified || user.isVerified,
      status: user.isOnline ? 'online' : 'offline'
    }));

    res.json({ users });
  } catch (error) {
    console.error('Erreur lors de la récupération des utilisateurs:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// Socket.IO pour le chat en temps réel
io.on('connection', (socket) => {
  console.log('Utilisateur connecté:', socket.id);

  socket.on('join_room', (roomId) => {
    socket.join(`room_${roomId}`);
    console.log(`Utilisateur ${socket.id} a rejoint le salon ${roomId}`);
  });

  socket.on('leave_room', (roomId) => {
    socket.leave(`room_${roomId}`);
    console.log(`Utilisateur ${socket.id} a quitté le salon ${roomId}`);
  });

  socket.on('typing_start', (data) => {
    socket.to(`room_${data.roomId}`).emit('user_typing', {
      username: data.username,
      isTyping: true
    });
  });

  socket.on('typing_stop', (data) => {
    socket.to(`room_${data.roomId}`).emit('user_typing', {
      username: data.username,
      isTyping: false
    });
  });

  socket.on('disconnect', () => {
    console.log('Utilisateur déconnecté:', socket.id);
  });
});

// Routes existantes (je garde les principales)
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role,
        isVerified: req.user.isVerified,
        verified: req.user.verified,
        createdAt: req.user.createdAt,
        lastLogin: req.user.lastLogin
      }
    });
  } catch (error) {
    console.error('Erreur lors de la récupération du profil:', error);
    res.status(500).json({
      error: 'Erreur interne du serveur'
    });
  }
});

// Initialiser les salons par défaut
const initializeDefaultRooms = async () => {
  try {
    const existingRooms = await ChatRoom.countDocuments();

    if (existingRooms === 0) {
      // Créer un utilisateur système si nécessaire
      let systemUser = await User.findOne({ username: 'SYSTEM' });
      if (!systemUser) {
        systemUser = new User({
          username: 'SYSTEM',
          email: 'system@qvslv.com',
          password: 'SystemPassword123!',
          role: 'admin',
          isVerified: true,
          verified: true
        });
        await systemUser.save();
      }

      const defaultRooms = [
        {
          name: 'Général',
          description: 'Discussions générales et actualités',
          category: 'Général',
          isPrivate: false,
          verified: true,
          createdBy: systemUser._id,
          members: [systemUser._id]
        },
        {
          name: 'Investigations Économiques',
          description: 'Analyses financières et économiques approfondies',
          category: 'Économie',
          isPrivate: false,
          verified: true,
          createdBy: systemUser._id,
          members: [systemUser._id]
        },
        {
          name: 'Lanceurs d\'Alerte',
          description: 'Espace sécurisé pour les témoignages',
          category: 'Confidentiel',
          isPrivate: true,
          verified: true,
          createdBy: systemUser._id,
          members: [systemUser._id]
        },
        {
          name: 'Vérification Sources',
          description: 'Validation collaborative des informations',
          category: 'Vérification',
          isPrivate: false,
          verified: true,
          createdBy: systemUser._id,
          members: [systemUser._id]
        }
      ];

      await ChatRoom.insertMany(defaultRooms);
      console.log('✅ Salons par défaut créés');
    }
  } catch (error) {
    console.error('❌ Erreur lors de la création des salons par défaut:', error);
  }
};


// Route pour récupérer les statistiques utilisateur (existante)
app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const activities = await Activity.find({ userId }).sort({ timestamp: -1 });
    
    const stats = {
      totalContributions: 0,
      totalDownloads: 0,
      totalUploads: 0,
      totalMessages: 0,
      accountAge: 0,
      lastActivityDate: req.user.lastLogin || req.user.createdAt,
      favoriteCategory: null
    };

    const activityCounts = {
      contribution: 0,
      download: 0,
      upload: 0,
      chat_message: 0
    };

    const categoryCounts = {};

    activities.forEach(activity => {
      if (activityCounts.hasOwnProperty(activity.type)) {
        activityCounts[activity.type]++;
      }

      if (activity.category && activity.category !== 'inscription') {
        categoryCounts[activity.category] = (categoryCounts[activity.category] || 0) + 1;
      }
    });

    stats.totalContributions = activityCounts.contribution;
    stats.totalDownloads = activityCounts.download;
    stats.totalUploads = activityCounts.upload;
    stats.totalMessages = activityCounts.chat_message;

    const accountCreated = new Date(req.user.createdAt);
    const now = new Date();
    stats.accountAge = Math.floor((now.getTime() - accountCreated.getTime()) / (1000 * 60 * 60 * 24));

    if (Object.keys(categoryCounts).length > 0) {
      stats.favoriteCategory = Object.keys(categoryCounts).reduce((a, b) => 
        categoryCounts[a] > categoryCounts[b] ? a : b
      );
    }

    if (activities.length > 0) {
      stats.lastActivityDate = activities[0].timestamp;
    }

    res.json({ stats });

  } catch (error) {
    console.error('Erreur lors de la récupération des statistiques:', error);
    res.status(500).json({
      error: 'Erreur interne du serveur'
    });
  }
});

// Route test
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "OK", 
    message: "Serveur opérationnel avec chat.",
    timestamp: new Date().toISOString()
  });
});

// Connexion à MongoDB Atlas
mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log("✅ Connecté à MongoDB Atlas");
    
    // Initialiser les salons par défaut
    await initializeDefaultRooms();
   
    // Lancer le serveur seulement après la connexion à la base
    server.listen(PORT, () => {
      console.log(`🚀 Serveur en ligne sur le port ${PORT}`);
      console.log(`🔒 JWT Secret configuré: ${JWT_SECRET ? 'Oui' : 'Non'}`);
      console.log(`💬 Chat temps réel activé`);
      console.log(`📊 Routes statistiques activées`);
    });
  })
  .catch((err) => {
    console.error("❌ Échec de connexion à MongoDB :", err.message);
    process.exit(1);
  });

// Gestion des erreurs globales
app.use((error, req, res, next) => {
  console.error('Erreur non gérée:', error);
  res.status(500).json({
    error: 'Erreur interne du serveur'
  });
});

// Gestion des routes non trouvées
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route non trouvée'
  });
});