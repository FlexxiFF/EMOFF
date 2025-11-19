# Deployment Guide

## Important Note

This application consists of two continuously running services:
1. `main.py` - The main bot service
2. `web_panel.py` - The Flask web interface

**Netlify Limitation**: Netlify is designed for static sites and serverless functions, not for continuously running backend services. This application will NOT work properly on Netlify.

## Recommended Deployment Options

### Option 1: Traditional Server Deployment (Recommended)
Deploy to a VPS or dedicated server where you can run both services continuously:

1. Clone the repository to your server
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run both services:
   ```bash
   nohup python main.py &
   nohup python web_panel.py &
   ```

### Option 2: Cloud Platform (Heroku, AWS, Google Cloud)
These platforms support continuously running Python applications.

### Option 3: Docker Deployment
Create Docker containers for both services and deploy them to a container platform.

## Netlify Alternative

If you still want to use Netlify for the frontend only (with limited functionality):

1. The static HTML templates can be deployed to Netlify
2. However, all backend functionality (user management, bot control) will NOT work
3. This would only provide a static preview of the UI

## GitHub Deployment Steps

1. Create a new repository on GitHub
2. Initialize git in your project folder:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   ```
3. Add the GitHub remote:
   ```bash
   git remote add origin https://github.com/yourusername/your-repo-name.git
   ```
4. Push to GitHub:
   ```bash
   git push -u origin main
   ```

## Environment Variables

For production deployment, you should set these environment variables:
- `FLASK_SECRET_KEY` - Secret key for Flask sessions
- `ADMIN_PASSWORD` - Admin password (instead of hardcoded default)

## Security Considerations

1. Change the default admin password immediately after deployment
2. Use a strong secret key for Flask sessions
3. Consider adding SSL/TLS for secure communication
4. Implement proper user authentication and authorization