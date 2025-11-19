# FLEXXI Emote Bot Control Panel

A web-based control panel for managing emote bots.

## Features
- User authentication system
- Admin panel for user management
- Emote control interface
- Real-time bot status monitoring

## Setup Instructions

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the main bot service:
   ```
   python main.py
   ```
4. Run the web panel:
   ```
   python web_panel.py
   ```
5. Access the web panel at http://127.0.0.1:5000

## Deployment Notes

This application requires two continuously running services:
1. `main.py` - The bot service
2. `web_panel.py` - The web interface

For full functionality, both services must be running simultaneously.

## Default Credentials
- Admin login: `admin` / `admin123` (CHANGE THIS AFTER FIRST LOGIN)