# 🔒 Security Awareness Training Platform

A comprehensive web application for security awareness training, featuring phishing simulations and interactive training modules for small businesses.

## Features

### 🎯 Core Functionality
- **User Authentication** - Secure registration and login system
- **Training Modules** - Interactive lessons on:
  - Phishing Basics
  - Password Security
  - Social Engineering
- **Quiz System** - Test knowledge after each module (70% to pass)
- **Phishing Simulator** - Real-world phishing email scenarios with:
  - Multiple difficulty levels
  - Timed challenges
  - Instant feedback with red flag analysis
- **Progress Tracking** - Visual dashboards showing completion rates
- **Admin Panel** - Monitor team progress and phishing detection rates

### 🎨 Design
- Modern, responsive UI
- Clean gradient theme
- Mobile-friendly layout
- Real-time statistics

## Quick Start

### Prerequisites
- Python 3.8+
- pip

### Installation

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Run the application:**
```bash
python app.py
```

3. **Access the platform:**
```
Open your browser to: http://localhost:5000
```

### Default Admin Account
- **Username:** admin
- **Password:** admin123

## Usage

### For Users
1. Register a new account
2. Complete training modules in any order
3. Take quizzes to test your knowledge (70% required to pass)
4. Practice with phishing simulator scenarios
5. Track your progress on the dashboard

### For Admins
1. Login with admin credentials
2. Access Admin Panel from navigation
3. Monitor all user progress
4. Review phishing simulation statistics
5. Identify users who need additional training

## Project Structure

```
security-training-platform/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Landing page
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   ├── dashboard.html    # User dashboard
│   ├── module.html       # Training module view
│   ├── quiz.html         # Quiz interface
│   ├── phishing.html     # Phishing simulator list
│   ├── phishing_scenario.html  # Individual scenario
│   ├── phishing_result.html    # Scenario results
│   └── admin.html        # Admin panel
├── static/
│   └── css/
│       └── style.css     # Custom styles
└── security_training.db  # SQLite database (created on first run)
```

## Database Schema

### Users
- ID, username, email, password (hashed), is_admin, created_at

### Modules
- ID, title, description, content (HTML), quiz_questions (JSON)

### UserProgress
- ID, user_id, module_id, completed, score, completed_at

### PhishingScenarios
- ID, title, from_email, subject, body, red_flags (JSON), difficulty

### PhishingResults
- ID, user_id, scenario_id, identified_correctly, time_taken, timestamp

## Customization

### Adding New Training Modules
Edit the `init_db()` function in `app.py` to add modules:
```python
{
    'title': 'Your Module Title',
    'description': 'Module description',
    'content': '''<h3>Your HTML content here</h3>''',
    'quiz_questions': [
        {
            'question': 'Your question?',
            'options': ['Option 1', 'Option 2', 'Option 3', 'Option 4'],
            'correct': 1  # Index of correct answer (0-based)
        }
    ]
}
```

### Adding Phishing Scenarios
Add to the `scenarios` list in `init_db()`:
```python
{
    'title': 'Scenario Name',
    'from_email': 'attacker@suspicious-domain.com',
    'subject': 'Email subject line',
    'body': '''Email body content...''',
    'red_flags': [
        'Red flag 1',
        'Red flag 2',
        'Red flag 3'
    ],
    'difficulty': 'Easy'  # Easy, Medium, or Hard
}
```

## Security Notes

- Passwords are hashed using Werkzeug's security functions
- Session management with secure secret keys
- SQLite database for easy deployment
- Input validation on all forms

## Deployment Recommendations

For production deployment:
1. Change the secret key in `app.py`
2. Set `debug=False` in `app.run()`
3. Use a production WSGI server (Gunicorn, uWSGI)
4. Consider PostgreSQL instead of SQLite
5. Add HTTPS/SSL certificates
6. Implement rate limiting
7. Add email notification features
8. Set up automated database backups

## Future Enhancements

- [ ] Email notifications for completed training
- [ ] Certificate generation upon completion
- [ ] More training modules (ransomware, data protection, GDPR)
- [ ] Scheduled phishing campaigns
- [ ] Detailed analytics and reporting
- [ ] Multi-language support
- [ ] Integration with LDAP/Active Directory
- [ ] Custom branding options
- [ ] Export reports to PDF/CSV

## License

This project is open source and available for educational purposes.

## Contributing

Feel free to fork, modify, and expand this platform for your organization's needs!

## Support

For issues or questions, create an issue in the repository.

---

**Built with:** Python, Flask, SQLAlchemy, HTML/CSS/JavaScript  
**Perfect for:** Small businesses, IT departments, security teams, MSPs
