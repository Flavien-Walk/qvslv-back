const express = require("express");
const router = express.Router();
const Message = require("../models/Message");

// POST /chat : Enregistrer un message
router.post("/", async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) {
      return res.status(400).json({ error: "Le message est vide." });
    }

    const message = new Message({ content });
    await message.save();

    res.status(201).json(message);
  } catch (error) {
    console.error("Erreur lors de l'enregistrement :", error);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

// GET /chat : Récupérer tous les messages
router.get("/", async (req, res) => {
  try {
    const messages = await Message.find().sort({ createdAt: 1 });
    res.json(messages);
  } catch (error) {
    console.error("Erreur lors de la récupération :", error);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

module.exports = router;
