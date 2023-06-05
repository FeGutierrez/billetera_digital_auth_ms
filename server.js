require('inspector').open()
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

const isTokenValid = (token) => {
    try {
      jwt.verify(token, 'secret_key');
      return true; // Token is valid
    } catch (err) {
      return false; // Token is invalid or has expired
    }
  };

// Connect to MongoDB
mongoose.connect('mongodb://mongo:27017/auth-service', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Failed to connect to MongoDB', err));

// Define User schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    unique: true
  },
  password: String,
});

const User = mongoose.model('User', userSchema);

// Middleware to parse JSON bodies
app.use(express.json());

// Signup endpoint
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Error while signing up', error);
    res.status(500).json({ message: 'An error occurred' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    console.log("\n\nI'm here!");
    console.log(req.body);

    if (!user) {
      return res.status(401).json({ message: 'Authentication failed. User does not exist' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'Authentication failed. Invalid password.' });
    }

    const token = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1m' });

    res.status(200).json({ userId: user._id, username: user.username, token: token });
  } catch (error) {
    console.error('Error while logging in', error);
    res.status(500).json({ message: 'An error occurred, check the console.' });
  }
});

//Check if the token is valid - to be used by the API Gateway when in conjunction with other services
app.get('/validate_token', (req, res) => {
    const { token } = req.body;
    console.log(`token is ${token}`)
    res.status(200).json({ is_valid: isTokenValid(token) })
});

// route example
app.get('/route', (req, res) => {
  res.json({ message: 'route accessed successfully' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
