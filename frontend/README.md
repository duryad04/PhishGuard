# PhishGuard

PhishGuard is a phishing detection tool that analyzes URLs for suspicious patterns and provides a risk assessment. It includes a React-based frontend and a Flask-based backend, with a SQLite database for storing scan history.

## Features

- **Frontend**: Built with React and Vite for a fast and modern user interface.
- **Backend**: Powered by Flask, with URL analysis logic to detect phishing indicators.
- **Database**: SQLite database for storing scan history.
- **Security**: Implements rate limiting, SSRF protection, and security headers.
- **Logging**: Logs high-risk URLs and errors for monitoring.

## Project Structure
 ├── backend/ │ ├── app.py # Flask app for backend API │ ├── database.py # SQLite database operations │ ├── detector.py # URL analysis logic │ ├── phishguard.log # Log file for backend │ ├── requirements.txt # Python dependencies
 
 ├── frontend/ │ ├── src/ # React source code │ ├── public/ # Static assets │ ├── index.html # Main HTML file │ ├── package.json # Node.js dependencies │ ├── vite.config.js # Vite configuration ├── .gitignore # Git ignore rules ├── README.md 

 # Project documentation

## Installation

### Backend

1. Navigate to the `backend` directory:
   ```bash
   cd backend

2. Create and activate a virtual environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install dependencies:
pip install -r requirements.txt

4. Run the backend server:
python app.py

The backend will be available at the given link. Example: http://127.0.0.1:5000.

### Frontend

1. Navigate to the frontend directory:
cd frontend

2. Install dependencies:
npm install

3. Start the development server:
npm run dev

The frontend will be available at the given link. Example: http://localhost:5173.

# Usage
Open the frontend in your browser.
Paste a suspicious URL into the input box and click "Scan URL".
View the analysis result, including the risk score and reasons.
Check the scan history for previously analyzed URLs.

# Security Features
Rate Limiting: Prevents abuse with limits on API requests.
SSRF Protection: Blocks internal/private network addresses.
Security Headers: Adds headers for enhanced security.

# Dependencies
## Backend
Flask
Flask-CORS
Flask-Limiter
SQLite

## Frontend
React
Vite
ESLint