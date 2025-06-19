const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    minlength: 3,
    maxlength: 20,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  motto: {
    type: String,
    maxlength: 100,
    default: "La vérité est là-bas, il suffit de savoir regarder"
  },
  level: {
    type: Number,
    default: 1
  },
  points: {
    type: Number,
    default: 0
  },
  posts: {
    type: Number,
    default: 0
  },
  joinDate: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  isActive: {
    type: Boolean,
    default: true
  },
  preferences: {
    darkMode: { type: Boolean, default: true },
    notifications: { type: Boolean, default: true },
    autoSave: { type: Boolean, default: false },
    analytics: { type: Boolean, default: true }
  }
}, {
  timestamps: true
});

// Index pour améliorer les performances
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });

// Méthode pour calculer les jours depuis l'inscription
userSchema.virtual('daysSinceJoin').get(function() {
  const diffTime = Math.abs(new Date() - this.joinDate);
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  return diffDays;
});

// Méthode pour formater les stats utilisateur
userSchema.methods.getStats = function() {
  return {
    posts: this.posts,
    level: this.level,
    points: this.points.toLocaleString(),
    days: this.daysSinceJoin
  };
};

module.exports = mongoose.model("User", userSchema);