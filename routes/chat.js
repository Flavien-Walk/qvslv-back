const express = require("express");
const router = express.Router();
const Message = require("../models/Message");

// GET /chat — Récupérer les messages
router.get("/", async (req, res) => {
  try {
    const messages = await Message.find().sort({ createdAt: 1 });
    res.json(messages);
  } catch (error) {
    console.error("Erreur lors de la récupération des messages :", error);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

// POST /chat — Envoyer un message
router.post("/", async (req, res) => {
  try {
    const { content, pseudo, color } = req.body;
    if (!content || !pseudo || !color) {
      return res.status(400).json({ error: "Contenu, pseudo et couleur sont requis." });
    }

    const message = new Message({ content, pseudo, color });
    await message.save();

    res.status(201).json(message);
  } catch (error) {
    console.error("Erreur lors de l'envoi du message :", error);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

module.exports = router;
