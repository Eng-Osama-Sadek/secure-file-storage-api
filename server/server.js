const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// === Middlewares ===
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../client')));

// Ensure Upload Directory Exists
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Memory Database Store
let db = {
    users: [], // قائمة الحسابات المسجلة
    files: [],
    folders: [
        { id: '1', name: 'New folder 1', fileCount: 3 },
        { id: '2', name: 'testing', fileCount: 0 }
    ]
};

// OWASP Security: Multer Storage Config with UUID renaming
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        const safeName = `${uuidv4()}${ext}`;
        cb(null, safeName);
    }
});

// OWASP Security: Extension Whitelist Validation
const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.pdf', '.docx', '.mp4', '.zip'];

const upload = multer({
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // Limit: 100 MB
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (ALLOWED_EXTENSIONS.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only allowed extensions are permitted.'));
        }
    }
});

// === Authentication Endpoints ===

// Register User (إنشاء حساب جديد)
app.post('/api/auth/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    const existingUser = db.users.find(u => u.email === email);
    if (existingUser) {
        return res.status(400).json({ error: 'User already exists.' });
    }

    const newUser = { id: uuidv4(), email, password };
    db.users.push(newUser);
    res.status(201).json({ message: 'Registration successful! Please log in.' });
});

// Login User (تسجيل الدخول)
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.users.find(u => u.email === email && u.password === password);

    if (!user) {
        return res.status(401).json({ error: 'Invalid email or password.' });
    }

    res.json({ token: `token-${user.id}`, email: user.email });
});

// === REST API Endpoints ===

// Get All Files
app.get('/api/files', (req, res) => {
    res.json(db.files);
});

// Upload File Endpoint
app.post('/api/files/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded or file extension rejected.' });
    }

    const newFile = {
        id: uuidv4(),
        originalName: req.file.originalname,
        storedName: req.file.filename,
        size: req.file.size,
        mimeType: req.file.mimetype,
        isPublic: false,
        createdAt: new Date(),
        path: req.file.path
    };

    db.files.push(newFile);
    res.status(201).json(newFile);
});

// Delete File
app.delete('/api/files/:id', (req, res) => {
    const fileIndex = db.files.findIndex(f => f.id === req.params.id);
    if (fileIndex === -1) return res.status(404).json({ error: 'File not found' });

    const file = db.files[fileIndex];
    if (fs.existsSync(file.path)) {
        fs.unlinkSync(file.path);
    }

    db.files.splice(fileIndex, 1);
    res.json({ message: 'File deleted successfully' });
});

// Serve Public Files Safely
app.get('/api/public/files/:storedName', (req, res) => {
    const file = db.files.find(f => f.storedName === req.params.storedName && f.isPublic);
    if (!file) return res.status(403).json({ error: 'Access denied or private file.' });
    
    res.sendFile(file.path);
});

// === Global Error Handler (Catches Multer & Standard Errors) ===
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size allowed is 100 MB.' });
        }
        return res.status(400).json({ error: `Upload error: ${err.message}` });
    } else if (err) {
        return res.status(400).json({ error: err.message });
    }
    next();
});

// === SPA Fallback Route (Express 4 & Express 5 Compatible) ===
app.use((req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running securely on http://localhost:${PORT}`);
});