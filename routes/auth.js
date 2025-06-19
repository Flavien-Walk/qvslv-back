const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { authenticateToken } = require("../middleware/auth");

const router = express.Router();

// Fonction pour générer un token JWT
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

// Route d'inscription
router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation des données
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Tous les champs sont requis"
      });
    }

    if (username.length < 3 || username.length > 20) {
      return res.status(400).json({
        success: false,
        message: "Le pseudo doit contenir entre 3 et 20 caractères"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Le mot de passe doit contenir au moins 6 caractères"
      });
    }

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: existingUser.email === email 
          ? "Cette adresse email est déjà utilisée" 
          : "Ce pseudo est déjà pris"
      });
    }

    // Hacher le mot de passe
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Créer l'utilisateur
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    // Générer le token
    const token = generateToken(user._id);

    // Réponse sans le mot de passe
    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      motto: user.motto,
      level: user.level,
      points: user.points,
      joinDate: user.joinDate,
      preferences: user.preferences
    };

    res.status(201).json({
      success: true,
      message: "Compte créé avec succès",
      token,
      user: userResponse
    });

  } catch (error) {
    console.error("Erreur lors de l'inscription:", error);
    res.status(500).json({
      success: false,
      message: "Erreur serveur lors de la création du compte"
    });
  }
});

// Route de connexion
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation des données
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email et mot de passe requis"
      });
    }

    // Trouver l'utilisateur
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Email ou mot de passe incorrect"
      });
    }

    // Vérifier le mot de passe
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Email ou mot de passe incorrect"
      });
    }

    // Vérifier si le compte est actif
    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: "Compte désactivé"
      });
    }

    // Mettre à jour la dernière connexion
    user.lastLogin = new Date();
    await user.save();

    // Générer le token
    const token = generateToken(user._id);

    // Réponse sans le mot de passe
    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      motto: user.motto,
      level: user.level,
      points: user.points,
      posts: user.posts,
      joinDate: user.joinDate,
      lastLogin: user.lastLogin,
      preferences: user.preferences,
      stats: user.getStats()
    };

    res.json({
      success: true,
      message: "Connexion réussie",
      token,
      user: userResponse
    });

  } catch (error) {
    console.error("Erreur lors de la connexion:", error);
    res.status(500).json({
      success: false,
      message: "Erreur serveur lors de la connexion"
    });
  }
});

// Route pour vérifier le token
router.get("/verify", authenticateToken, async (req, res) => {
  try {
    const userResponse = {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      motto: req.user.motto,
      level: req.user.level,
      points: req.user.points,
      posts: req.user.posts,
      joinDate: req.user.joinDate,
      lastLogin: req.user.lastLogin,
      preferences: req.user.preferences,
      stats: req.user.getStats()
    };

    res.json({
      success: true,
      user: userResponse
    });
  } catch (error) {
    console.error("Erreur lors de la vérification:", error);
    res.status(500).json({
      success: false,
      message: "Erreur serveur"
    });
  }
});

// Route de déconnexion (optionnelle, principalement côté client)
router.post("/logout", authenticateToken, async (req, res) => {
  try {
    // Ici vous pourriez ajouter une logique de blacklist de tokens si nécessaire
    res.json({
      success: true,
      message: "Déconnexion réussie"
    });
  } catch (error) {
    console.error("Erreur lors de la déconnexion:", error);
    res.status(500).json({
      success: false,
      message: "Erreur serveur"
    });
  }
});

module.exports = router;