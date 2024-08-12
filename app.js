const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const dbPath = path.join(__dirname, 'userData.db');
let db = null;

app.use(express.json());

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log('Server Running on http://localhost:3000/');
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

// API 1: Register a new user
app.post('/register/', async (req, res) => {
  const { username, name, password, gender, location } = req.body;
  const selectQuery = `SELECT * FROM user WHERE username = ?`;
  try {
    const check = await db.get(selectQuery, [username]);
    if (check === undefined) {
      if (password.length > 5) {
        const hashedPassword = await bcrypt.hash(password, 10);
        const insertQuery = `
          INSERT INTO user (username, name, password, gender, location)
          VALUES (?, ?, ?, ?, ?)
        `;
        await db.run(insertQuery, [username, name, hashedPassword, gender, location]);
        res.send('User created successfully');
      } else {
        res.status(400);
        res.send('Password is too short');
      }
    } else {
      res.status(400);
      res.send('User already exists');
    }
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

// API 2: Login
app.post('/login/', async (req, res) => {
  const { username, password } = req.body;
  const selectQuery = `SELECT * FROM user WHERE username = ?`;
  try {
    const check = await db.get(selectQuery, [username]);
    if (check === undefined) {
      res.status(400);
      res.send('Invalid user');
    } else {
      const isPasswordMatched = await bcrypt.compare(password, check.password);
      if (isPasswordMatched === true) {
        res.send('Login success!');
      } else {
        res.status(400);
        res.send('Invalid password');
      }
    }
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

// API 3: Change Password
app.put("/change-password", async (request, response) => {
  const { username, oldPassword, newPassword } = request.body;
  if (newPassword.length < 5) {
    response.status(400);
    response.send("Password is too short");
    return;
  }
  
  const selectQuery = `SELECT * FROM user WHERE username = ?`;
  try {
    const dbUsername = await db.get(selectQuery, [username]);
    if (!dbUsername) {
      response.status(400);
      response.send("Invalid user");
    } else {
      const isPasswordMatch = await bcrypt.compare(oldPassword, dbUsername.password);
      if (!isPasswordMatch) {
        response.status(400);
        response.send("Invalid current password");
      } else {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const updatePasswordQuery = `
          UPDATE user
          SET password = ?
          WHERE username = ?
        `;
        await db.run(updatePasswordQuery, [hashedPassword, username]);
        response.status(200);
        response.send("Password updated");
      }
    }
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});

module.exports = app;
