const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'persist_ventures_super_secret_key_2026';

app.use(cors());
app.use(express.json());

// In-Memory Database for Demo Purposes
const users = [];
const files = [];

// Storage Directory Setup
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// OWASP Security: Multer Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    // Rename to UUID to prevent Path Traversal and Collisions
    const safeFilename = `${uuidv4()}${ext}`;
    cb(null, safeFilename);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB Limit
  fileFilter: (req, file, cb) => {
    // OWASP Extension Allowlist
    const allowedExts = ['.jpg', '.png', '.pdf', '.docx', '.zip', '.mp4', '.txt'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('File extension is not allowed by security policy.'));
    }
  }
});

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied, token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// --- AUTH ENDPOINTS ---
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), username, password: hashedPassword };
  users.push(user);
  res.status(201).json({ message: 'User registered successfully' });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token, username: user.username });
});

// --- FILE STORAGE ENDPOINTS ---
app.post('/api/files/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const isPublic = req.body.isPublic === 'true';
  const fileRecord = {
    id: uuidv4(),
    originalName: req.file.originalname,
    storedName: req.file.filename,
    size: req.file.size,
    mimeType: req.file.mimetype,
    ownerId: req.user.id,
    isPublic: isPublic,
    createdAt: new Date()
  };

  files.push(fileRecord);
  res.status(201).json({ message: 'File uploaded successfully', file: fileRecord });
});

app.get('/api/files', authenticateToken, (req, res) => {
  const userFiles = files.filter(f => f.ownerId === req.user.id);
  res.json(userFiles);
});

app.patch('/api/files/:id/visibility', authenticateToken, (req, res) => {
  const file = files.find(f => f.id === req.params.id && f.ownerId === req.user.id);
  if (!file) return res.status(404).json({ error: 'File not found or unauthorized' });

  file.isPublic = req.body.isPublic;
  res.json({ message: 'Visibility updated successfully', file });
});

// OWASP Public/Private Authorization Handling
app.get('/api/files/download/:id', (req, res) => {
  const file = files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  if (!file.isPublic) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Private file: Token required' });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.id !== file.ownerId) {
        return res.status(403).json({ error: 'Access denied: You do not own this file' });
      }
    } catch (e) {
      return res.status(403).json({ error: 'Invalid authentication token' });
    }
  }

  const filePath = path.join(UPLOAD_DIR, file.storedName);
  res.download(filePath, file.originalName);
});

app.use(express.static(path.join(__dirname, '../client')));

app.listen(PORT, () => {
  console.log(`Server running securely on http://localhost:${PORT}`);
});