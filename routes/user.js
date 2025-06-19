const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { authenticateToken } = require("../middleware/auth");

const router = express.Router();

// Route pour mettre à jour le profil
router.put("/profile", authenticateToken, async (req, res) => {
  try {
    const { username, motto, preferences } = req.body;
    const userId = req.user._id;

    const updateData = {};

    // Vérifier et mettre à jour le username
    if (username && username !== req.user.username) {
      if (username.length < 3 || username.length > 20) {
        return res.status(400).json({
          success: false,
          message: "Le pseudo doit contenir entre 3 et 20 caractères"
        });
      }

      // Vérifier si le username est déjà pris
      const existingUser = await User.findOne({ 
        username, 
        _id: { $ne: userId } 
      });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: "Ce pseudo est déjà utilisé"
        });
      }

      updateData.username = username;
    }

    // Mettre à jour la devise
    if (motto !== undefined) {
      if (motto.length > 100) {
        return res.status(400).json({
          success: false,
          message: "La devise ne peut pas dépasser 100 caractères"
        });
      }
      updateData.motto = motto;
    }

    // Mettre à jour les préférences
    if (preferences) {
      updateData.preferences = {
        ...req.user.preferences,
        ...preferences
      };
    }

    // Effectuer la mise à jour
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: "Utilisateur non trouvé"
      });
    }

    const userResponse = {
      id: updatedUser._id,
      username: updatedUser.username,
      email: updatedUser.email,
      motto: updatedUser.motto,
      level: updatedUser.level,
      points: updatedUser.points,
      posts: updatedUser.posts,
      joinDate: updatedUser.joinDate,
      lastLogin: updatedUser.lastLogin,
      preferences: updatedUser.preferences,
      stats: updatedUser.getStats()
    };

    res.json({
      success: true,
      message: "Profil mis à jour avec succès",
      user: userResponse
    });

  } catch (error) {
    console.error("Erreur lors de la mise à jour du profil:", error);
    res.status(500).json({
      success: false,
      message: "Erreur serveur lors de la mise à jour"
    });
  }
});

// Route pour changer le mot de passe
router.put("/password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user._id;

    // Validation
    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Mot de passe actuel et nouveau mot de passe requis"
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Le nouveau mot de passe doit contenir au moins 6 caractères"
      });
    }

    // Récupérer l'utilisateur avec le mot de passe
    const user = await User.findById(userId);

    // Vérifier le mot de passe actuel
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Mot de passe actuel incorrect"
      });
    }

    // Hacher le nouveau mot de passe
    const saltRounds = 12;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

    // Mettre à jour le mot de passe
    await User.findByIdAndUpdate(userId, {
      password: hashedNewPassword
    });

    res.json({
      success: true,
      message: "Mot de passe mis à jour avec succès"
    });

  } catch (error) {
    console.error("Erreur lors du changement de mot de passe:", error);
    res.status(500).json({
      success: false,
      message: "Erreur serveur lors du changement de mot de passe"
    });
  }
});

// Route pour obtenir les statistiques utilisateur
router.get("/stats", authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    const stats = {
      posts: user.posts,
      level: user.level,
      points: user.points,
      days: user.daysSinceJoin,
      joinDate: user.joinDate,
      lastLogin: user.lastLogin
    };

    res.json({
      success: true,
      stats
    });

  } catch (error) {
    console.error("Erreur lors de la récupération des stats:", error);
    res.status(500).json({
      success: false,
      message: "Erreur serveur"
    });
  }
});

// Route pour supprimer le compte
router.delete("/account", authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;
    const userId = req.user._id;

    if (!password) {
      return res.status(400).json({
        success: false,
        message: "Mot de passe requis pour supprimer le compte"
      });
    }

    // Récupérer l'utilisateur avec le mot de passe
    const user = await User.findById(userId);

    // Vérifier le mot de passe
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Mot de passe incorrect"
      });
    }

    // Désactiver le compte au lieu de le supprimer
    await User.findByIdAndUpdate(userId, {
      isActive: false,
      email: `deleted_${Date.now()}_${user.email}`,
      username: `deleted_${Date.now()}_${user.username}`
    });

    res.json({
      success: true,
      message: "Compte supprimé avec succès"
    });

  } catch (error) {
    console.error("Erreur lors de la suppression du compte:", error);
    res.status(500).json({
      success: false,
      message: "Erreur serveur lors de la suppression"
    });
  }
});

module.exports = router;