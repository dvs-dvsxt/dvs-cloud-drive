# ☁️ DVS Cloud Drive — Web File Management Platform

> A full-featured **web-based file management (cloud drive)** platform built with Flask. Upload, download, preview, share, search, and manage your files — with robust security.

**DVS Cloud Drive** is a self-hosted web file manager. It provides user authentication, file upload/download, folder management, batch operations, in-browser preview (PDF / audio / video), file search, and shareable links — all protected by security controls that block access to system-critical directories.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 👤 **User System** | Register / login / logout / change password (hashed with `werkzeug`) |
| 📤 **File Upload** | Upload files with secure filename handling |
| 📁 **Folder Management** | Create / rename / delete folders & files |
| 📥 **Download** | Single & batch download (ZIP archive) |
| 👁️ **In-Browser Preview** | PDF / video / audio preview |
| 🔍 **Search** | Search files across the drive |
| 🔗 **File Sharing** | Generate shareable links (`/s/<share_id>`) |
| 🗑️ **Batch Delete** | Delete multiple items at once |
| 📊 **Storage Usage** | View storage usage via API |
| 🛡️ **Security** | Forbidden system directories (Linux & Windows) blocked |

---

## 🔌 Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Dashboard / file list |
| `/login` | GET/POST | User login |
| `/register` | GET/POST | User registration |
| `/change_password` | GET/POST | Change password |
| `/logout` | GET | Log out |
| `/upload` | POST | Upload files |
| `/create_folder` | POST | Create a folder |
| `/rename` | POST | Rename item |
| `/delete` | POST | Delete item |
| `/download/<path>` | GET | Download file/folder |
| `/preview/<path>` | GET | Preview file (PDF/video/audio) |
| `/search` | GET | Search files |
| `/batch_download` | POST | Batch download as ZIP |
| `/batch_delete` | POST | Batch delete |
| `/share` | POST | Create share link |
| `/unshare` | POST | Remove share |
| `/shared_files` | GET | List shared files |
| `/s/<share_id>` | GET | Access a shared file |
| `/api/storage_usage` | GET | Storage usage (JSON) |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- `flask`, `flask-cors`, `werkzeug`

### Install & Run

```bash
# Install dependencies
pip install flask flask-cors

# Run the platform
python app.py
```

Then open `http://localhost:5000` in your browser.

### Default Flow
1. **Register** an account
2. **Login**
3. Upload / create folders / share / preview files from the dashboard

---

## 🛡️ Security

- Passwords hashed with `werkzeug.security` (PBKDF2)
- Secure filename normalization via `werkzeug.utils.secure_filename`
- **Forbidden directories** blocked (path traversal protection):
  - Linux: `/root`, `/etc`, `/usr`, `/var`, `/proc`, `/sys`, etc.
  - Windows: `C:\Windows`, `C:\Program Files`, System32, etc.
- Session-based authentication & CSRF protection

---

## 📁 Project Structure

```
DVS-Cloud-Drive/
├── app.py              # Main Flask application
├── templates/          # HTML templates (Jinja2)
│   ├── base.html       # Layout
│   ├── index.html      # Dashboard / file list
│   ├── login.html / register.html / change_password.html
│   ├── preview_pdf.html / preview_video.html / preview_audio.html
│   ├── search_results.html / shared_files.html
│   ├── 404.html / 500.html
├── favicon.ico         # Site icon
└── README.md           # This document
```

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
