const express = require("express");
const router = express.Router();
const User = require("../models/User");

// POST /user : Enregistrer un pseudo
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

module.exports = router;
