const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Store hashed passwords
  websites: [
    {
      url: String,
      name: String,
      status: String,
      added: Date,
      lastChecked: Date,
      history: [
        {
          timestamp: Date,
          status: String,
          packetLoss: Number,
          responseTime: Number
        }
      ]
    }
  ]
});

module.exports = mongoose.model('User', userSchema);