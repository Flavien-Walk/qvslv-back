// server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
require("dotenv").config();

const app = express();
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

// Middleware CORS propre
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

// Headers manuels pour pré-requêtes OPTIONS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  next();
});

app.use(express.json({ limit: '10mb' }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 tentatives par IP
  message: { error: "Trop de tentatives de connexion. Réessayez dans 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requêtes par IP
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/auth', authLimiter);
app.use('/api/', generalLimiter);

// Schéma utilisateur
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Le nom d\'utilisateur est requis'],
    unique: true,
    trim: true,
    minlength: [3, 'Le nom d\'utilisateur doit contenir au moins 3 caractères'],
    maxlength: [30, 'Le nom d\'utilisateur ne peut pas dépasser 30 caractères'],
    match: [/^[a-zA-Z0-9_-]+$/, 'Le nom d\'utilisateur ne peut contenir que des lettres, chiffres, _ et -']
  },
  email: {
    type: String,
    required: [true, 'L\'email est requis'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Format d\'email invalide']
  },
  password: {
    type: String,
    required: [true, 'Le mot de passe est requis'],
    minlength: [8, 'Le mot de passe doit contenir au moins 8 caractères']
  },
  isVerified: {
    type: Boolean,
    default: false
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

// Schéma pour les activités utilisateur
const activitySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['upload', 'download', 'contribution', 'login'],
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

// Middleware pour hasher le mot de passe
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

// Méthode pour comparer les mots de passe
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Méthode pour générer le JWT
userSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      userId: this._id, 
      username: this.username,
      email: this.email 
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// Méthode pour vérifier si le compte est verrouillé
userSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// Méthode pour incrémenter les tentatives de connexion
userSchema.methods.incLoginAttempts = function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5 && !this.isLocked()) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 heures
  }
  
  return this.updateOne(updates);
};

// Méthode pour réinitialiser les tentatives de connexion
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

const User = mongoose.model('User', userSchema);
const Activity = mongoose.model('Activity', activitySchema);

// Middleware d'authentification
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

// Fonction pour enregistrer une activité
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

// Validation du mot de passe
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

// Routes d'authentification

// Inscription
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    // Validation des données
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

    // Validation du mot de passe
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        error: 'Mot de passe invalide',
        details: passwordValidation.errors
      });
    }

    // Vérifier si l'utilisateur existe déjà
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

    // Créer le nouvel utilisateur
    const user = new User({
      username,
      email: email.toLowerCase(),
      password,
      verificationToken: jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' })
    });

    await user.save();

    // Enregistrer l'activité d'inscription
    await logActivity(user._id, 'contribution', 'inscription', {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Générer le token d'authentification
    const token = user.generateAuthToken();

    res.status(201).json({
      message: 'Compte créé avec succès',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isVerified: user.isVerified,
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

// Connexion
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email et mot de passe requis'
      });
    }

    // Trouver l'utilisateur
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

    // Vérifier si le compte est verrouillé
    if (user.isLocked()) {
      return res.status(423).json({
        error: 'Compte temporairement verrouillé en raison de trop nombreuses tentatives de connexion'
      });
    }

    // Vérifier le mot de passe
    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      await user.incLoginAttempts();
      return res.status(401).json({
        error: 'Identifiants invalides'
      });
    }

    // Réinitialiser les tentatives de connexion en cas de succès
    if (user.loginAttempts > 0) {
      await user.resetLoginAttempts();
    }

    // Mettre à jour la dernière connexion
    user.lastLogin = new Date();
    await user.save();

    // Enregistrer l'activité de connexion
    await logActivity(user._id, 'login', null, {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Générer le token
    const token = user.generateAuthToken();

    res.json({
      message: 'Connexion réussie',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isVerified: user.isVerified,
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

// Profil utilisateur (protégé)
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        isVerified: req.user.isVerified,
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

// Route pour récupérer les statistiques utilisateur
app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Récupérer les activités de l'utilisateur
    const activities = await Activity.find({ userId }).sort({ timestamp: -1 });
    
    // Calculer les statistiques
    const stats = {
      totalContributions: 0,
      totalDownloads: 0,
      totalUploads: 0,
      accountAge: 0,
      lastActivityDate: req.user.lastLogin || req.user.createdAt,
      favoriteCategory: null
    };

    // Compter les différents types d'activités
    const activityCounts = {
      contribution: 0,
      download: 0,
      upload: 0
    };

    const categoryCounts = {};

    activities.forEach(activity => {
      if (activity.type === 'contribution') {
        activityCounts.contribution++;
      } else if (activity.type === 'download') {
        activityCounts.download++;
      } else if (activity.type === 'upload') {
        activityCounts.upload++;
      }

      // Compter les catégories
      if (activity.category && activity.category !== 'inscription') {
        categoryCounts[activity.category] = (categoryCounts[activity.category] || 0) + 1;
      }
    });

    stats.totalContributions = activityCounts.contribution;
    stats.totalDownloads = activityCounts.download;
    stats.totalUploads = activityCounts.upload;

    // Calculer l'âge du compte en jours
    const accountCreated = new Date(req.user.createdAt);
    const now = new Date();
    stats.accountAge = Math.floor((now.getTime() - accountCreated.getTime()) / (1000 * 60 * 60 * 24));

    // Trouver la catégorie favorite
    if (Object.keys(categoryCounts).length > 0) {
      stats.favoriteCategory = Object.keys(categoryCounts).reduce((a, b) => 
        categoryCounts[a] > categoryCounts[b] ? a : b
      );
    }

    // Dernière activité
    if (activities.length > 0) {
      stats.lastActivityDate = activities[0].timestamp;
    }

    res.json({
      stats
    });

  } catch (error) {
    console.error('Erreur lors de la récupération des statistiques:', error);
    res.status(500).json({
      error: 'Erreur interne du serveur'
    });
  }
});

// Route pour enregistrer une activité utilisateur
app.post('/api/user/activity', authenticateToken, async (req, res) => {
  try {
    const { type, category, details } = req.body;
    const userId = req.user._id;

    // Validation du type d'activité
    const validTypes = ['upload', 'download', 'contribution', 'login'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({
        error: 'Type d\'activité invalide'
      });
    }

    // Créer la nouvelle activité
    const activity = new Activity({
      userId,
      type,
      category: category || null,
      details: details || {}
    });

    await activity.save();

    res.status(201).json({
      message: 'Activité enregistrée avec succès',
      activity: {
        id: activity._id,
        type: activity.type,
        category: activity.category,
        timestamp: activity.timestamp
      }
    });

  } catch (error) {
    console.error('Erreur lors de l\'enregistrement de l\'activité:', error);
    res.status(500).json({
      error: 'Erreur interne du serveur'
    });
  }
});

// Route pour récupérer l'historique d'activités
app.get('/api/user/activities', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;
    const { limit = 50, page = 1, type } = req.query;

    // Construire la requête
    const query = { userId };
    if (type) {
      query.type = type;
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const activities = await Activity.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip(skip)
      .select('type category details timestamp');

    const total = await Activity.countDocuments(query);

    res.json({
      activities,
      pagination: {
        current: parseInt(page),
        total: Math.ceil(total / parseInt(limit)),
        count: activities.length,
        totalRecords: total
      }
    });

  } catch (error) {
    console.error('Erreur lors de la récupération des activités:', error);
    res.status(500).json({
      error: 'Erreur interne du serveur'
    });
  }
});

// Route pour générer des données de test (à supprimer en production)
app.post('/api/user/generate-test-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;
    const categories = ['Musique', 'Vidéo', 'Documents', 'Images', 'Logiciels', 'Education', 'Gaming'];
    const types = ['upload', 'download', 'contribution'];
    
    const activities = [];
    
    // Générer 100 activités aléatoires sur les 6 derniers mois
    for (let i = 0; i < 100; i++) {
      const randomDate = new Date();
      randomDate.setDate(randomDate.getDate() - Math.floor(Math.random() * 180));
      
      activities.push({
        userId,
        type: types[Math.floor(Math.random() * types.length)],
        category: categories[Math.floor(Math.random() * categories.length)],
        timestamp: randomDate,
        details: {
          generated: true,
          testData: true
        }
      });
    }
    
    await Activity.insertMany(activities);
    
    res.json({
      message: 'Données de test générées avec succès',
      count: activities.length
    });

  } catch (error) {
    console.error('Erreur lors de la génération des données de test:', error);
    res.status(500).json({
      error: 'Erreur interne du serveur'
    });
  }
});

// Vérification du token
app.post('/api/auth/verify-token', authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email
    }
  });
});

// Déconnexion (côté client principalement)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Déconnexion réussie' });
});

// Demande de réinitialisation de mot de passe
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        error: 'Email requis'
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      // Pour des raisons de sécurité, on ne révèle pas si l'email existe
      return res.json({
        message: 'Si cet email existe dans notre système, vous recevrez un lien de réinitialisation'
      });
    }

    // Générer un token de réinitialisation
    const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 heure
    await user.save();

    // Ici, vous devriez envoyer un email avec le lien de réinitialisation
    
    res.json({
      message: 'Si cet email existe dans notre système, vous recevrez un lien de réinitialisation'
    });

  } catch (error) {
    console.error('Erreur lors de la demande de réinitialisation:', error);
    res.status(500).json({
      error: 'Erreur interne du serveur'
    });
  }
});

// Route test
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "OK", 
    message: "Serveur opérationnel.",
    timestamp: new Date().toISOString()
  });
});

// Connexion à MongoDB Atlas
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("✅ Connecté à MongoDB Atlas");
   
    // Lancer le serveur seulement après la connexion à la base
    app.listen(PORT, () => {
      console.log(`🚀 Serveur en ligne sur le port ${PORT}`);
      console.log(`🔒 JWT Secret configuré: ${JWT_SECRET ? 'Oui' : 'Non'}`);
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