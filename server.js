// server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
require("dotenv").config();

const app = express()
app.set('trust proxy', 1); // 👉 Nécessaire pour les reverse proxies comme Render;
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
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));
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

// Index pour améliorer les performances
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });

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
  // Si on a un verrou et qu'il a expiré, on remet à zéro
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Si on atteint 5 tentatives et qu'on n'est pas déjà verrouillé, on verrouille
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
    // Pour le moment, on simule juste l'envoi
    
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

// Connexion à MongoDB Atlas
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("✅ Connecté à MongoDB Atlas");
   
    // Lancer le serveur seulement après la connexion à la base
    app.listen(PORT, () => {
      console.log(`🚀 Serveur en ligne sur le port ${PORT}`);
      console.log(`🔒 JWT Secret configuré: ${JWT_SECRET ? 'Oui' : 'Non'}`);
    });
  })
  .catch((err) => {
    console.error("❌ Échec de connexion à MongoDB :", err.message);
    process.exit(1);
  });

// Route test
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "OK", 
    message: "Serveur opérationnel.",
    timestamp: new Date().toISOString()
  });
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