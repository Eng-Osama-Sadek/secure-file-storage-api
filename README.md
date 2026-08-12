# 🔒 Secure File Storage API

A robust, secure, and production-ready RESTful API built with **Node.js** and **Express** for handling file uploads, downloads, and access control. Designed with OWASP security practices to prevent unauthorized access and filename exploitation.

---

## ✨ Features

- **Authentication & Security:** JWT-based user authentication with hashed passwords using `bcryptjs`.
- **OWASP Filename Sanitization:** Renames files using `uuidv4` to prevent Directory Traversal and overwrite attacks.
- **Strict File Validation:** Whitelists safe file extensions (`.jpg`, `.png`, `.pdf`, `.docx`, `.zip`, `.mp4`, `.txt`, `.csv`) and limits uploads to 100MB.
- **Privacy & Access Control:** Support for Public and Private files. Private files can only be accessed by their owner.
- **File Management:** List personal uploaded files, download, and delete files safely.
- **Error Handling:** Global error handler for Multer and express runtime exceptions.

---

## 🛠️ Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Authentication:** JSON Web Token (JWT) & Bcrypt.js
- **File Handling:** Multer
- **Security & Utils:** CORS, UUID

---

## 🚀 Getting Started

### 1. Prerequisites
Make sure you have Node.js installed on your machine.

### 2. Installation
Clone the repository and install dependencies:

```bash
git clone [https://github.com/YOUR_USERNAME/secure-file-storage.git](https://github.com/YOUR_USERNAME/secure-file-storage.git)
cd secure-file-storage
npm install
