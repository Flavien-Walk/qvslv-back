const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json());

// Connexion MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connecté à MongoDB"))
  .catch(err => console.error("❌ Erreur MongoDB :", err));

// Routes
const chatRoutes = require("./routes/chat");
app.use("/chat", chatRoutes);

// Lancer le serveur
app.listen(PORT, () => {
  console.log(`🚀 Serveur en ligne sur http://localhost:${PORT}`);
});
