const express = require("express");
const router = express.Router();
const User = require("../models/User");

// POST /user — Créer un nouvel utilisateur
router.post("/", async (req, res) => {
  try {
    const { pseudo, color } = req.body;
    if (!pseudo || !color) {
      return res.status(400).json({ error: "Le pseudo et la couleur sont requis." });
    }

    const user = new User({ pseudo, color });
    await user.save();

    res.status(201).json(user);
  } catch (error) {
    console.error("Erreur lors de l'enregistrement du pseudo :", error);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

// PATCH /user/:id — Mettre à jour le pseudo et la couleur
router.patch("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { pseudo, color } = req.body;

    if (!pseudo || !color) {
      return res.status(400).json({ error: "Le pseudo et la couleur sont requis." });
    }

    const updatedUser = await User.findByIdAndUpdate(
      id,
      { pseudo, color },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ error: "Utilisateur non trouvé." });
    }

    res.json(updatedUser);
  } catch (error) {
    console.error("Erreur lors de la mise à jour du profil :", error);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

module.exports = router;
