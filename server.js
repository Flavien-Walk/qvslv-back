const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://qvslv-back.onrender.com', 'https://your-frontend-domain.com'] 
    : ['http://localhost:3000', 'exp://'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Connexion MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connecté à MongoDB Atlas"))
  .catch(err => console.error("❌ Erreur MongoDB :", err));

// Routes
app.use("/api/auth", require("./routes/auth"));
app.use("/api/user", require("./routes/user"));

// Route de test
app.get("/", (req, res) => {
  res.json({
    message: "🚀 QVSLV API est en ligne",
    version: "1.0.0",
    server: "Render.com",
    database: "MongoDB Atlas",
    endpoints: {
      auth: "/api/auth",
      user: "/api/user",
      health: "/api/health"
    }
  });
});

// Route de test pour vérifier la connexion
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    message: "QVSLV Backend is running",
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(process.uptime())} seconds`,
    mongodb: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected",
    environment: process.env.NODE_ENV || "development"
  });
});

// Middleware de log pour debug
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Gestion des erreurs 404
app.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} non trouvée`,
    availableRoutes: [
      "GET /",
      "GET /api/health", 
      "POST /api/auth/register",
      "POST /api/auth/login",
      "GET /api/auth/verify",
      "PUT /api/user/profile"
    ]
  });
});

// Gestion globale des erreurs
app.use((error, req, res, next) => {
  console.error("❌ Erreur serveur:", error.message);
  console.error("Stack:", error.stack);
  
  res.status(error.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' 
      ? "Erreur interne du serveur" 
      : error.message,
    ...(process.env.NODE_ENV !== 'production' && { stack: error.stack })
  });
});

// Lancer le serveur
app.listen(PORT, () => {
  console.log(`🚀 Serveur QVSLV en ligne sur https://qvslv-back.onrender.com`);
  console.log(`📱 API disponible sur https://qvslv-back.onrender.com/api`);
  console.log(`🔍 Health check: https://qvslv-back.onrender.com/api/health`);
  console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connecté' : 'Déconnecté'}`);
});

module.exports = app;