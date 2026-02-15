from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets

app = Flask(__name__) 
app.jinja_env.globals.update(enumerate=enumerate)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_training.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    progress = db.relationship('UserProgress', backref='user', lazy=True)
    phishing_results = db.relationship('PhishingResult', backref='user', lazy=True)

class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    quiz_questions = db.Column(db.JSON, nullable=False)

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    module_id = db.Column(db.Integer, db.ForeignKey('module.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    score = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.DateTime)

class PhishingScenario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    from_email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    red_flags = db.Column(db.JSON, nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)

class PhishingResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scenario_id = db.Column(db.Integer, db.ForeignKey('phishing_scenario.id'), nullable=False)
    identified_correctly = db.Column(db.Boolean, nullable=False)
    time_taken = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    modules = Module.query.all()
    
    # Calculate progress
    completed_modules = UserProgress.query.filter_by(
        user_id=user.id, completed=True
    ).count()
    total_modules = len(modules)
    progress_percentage = (completed_modules / total_modules * 100) if total_modules > 0 else 0
    
    # Get phishing stats
    phishing_total = PhishingResult.query.filter_by(user_id=user.id).count()
    phishing_correct = PhishingResult.query.filter_by(
        user_id=user.id, identified_correctly=True
    ).count()
    phishing_score = (phishing_correct / phishing_total * 100) if phishing_total > 0 else 0
    
    return render_template('dashboard.html', 
                         user=user, 
                         modules=modules,
                         progress_percentage=progress_percentage,
                         phishing_score=phishing_score,
                         phishing_total=phishing_total)

@app.route('/module/<int:module_id>')
def module(module_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    module = Module.query.get_or_404(module_id)
    return render_template('module.html', module=module)

@app.route('/module/<int:module_id>/quiz', methods=['GET', 'POST'])
def quiz(module_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    module = Module.query.get_or_404(module_id)
    
    if request.method == 'POST':
        answers = request.form
        correct = 0
        total = len(module.quiz_questions)
        
        for i, question in enumerate(module.quiz_questions):
            if answers.get(f'question_{i}') == str(question['correct']):
                correct += 1
        
        score = int((correct / total) * 100)
        
        # Save progress
        progress = UserProgress.query.filter_by(
            user_id=session['user_id'], module_id=module_id
        ).first()
        
        if not progress:
            progress = UserProgress(
                user_id=session['user_id'],
                module_id=module_id
            )
            db.session.add(progress)
        
        progress.completed = (score >= 70)
        progress.score = score
        progress.completed_at = datetime.utcnow()
        db.session.commit()
        
        flash(f'Quiz completed! Score: {score}%', 'success' if score >= 70 else 'warning')
        return redirect(url_for('dashboard'))
    
    return render_template('quiz.html', module=module)

@app.route('/phishing')
def phishing():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    scenarios = PhishingScenario.query.all()
    return render_template('phishing.html', scenarios=scenarios)

@app.route('/phishing/<int:scenario_id>', methods=['GET', 'POST'])
def phishing_scenario(scenario_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    scenario = PhishingScenario.query.get_or_404(scenario_id)
    
    if request.method == 'POST':
        decision = request.form.get('decision')
        time_taken = request.form.get('time_taken', 0)
        
        # A legitimate email would have decision == 'legitimate'
        # A phishing email would have decision == 'phishing'
        # For now, all scenarios are phishing attempts
        identified_correctly = (decision == 'phishing')
        
        result = PhishingResult(
            user_id=session['user_id'],
            scenario_id=scenario_id,
            identified_correctly=identified_correctly,
            time_taken=int(time_taken)
        )
        db.session.add(result)
        db.session.commit()
        
        return render_template('phishing_result.html', 
                             scenario=scenario, 
                             correct=identified_correctly)
    
    return render_template('phishing_scenario.html', scenario=scenario)

@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Admin access required!', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    user_stats = []
    
    for user in users:
        if not user.is_admin:
            completed = UserProgress.query.filter_by(
                user_id=user.id, completed=True
            ).count()
            total_modules = Module.query.count()
            
            phishing_total = PhishingResult.query.filter_by(user_id=user.id).count()
            phishing_correct = PhishingResult.query.filter_by(
                user_id=user.id, identified_correctly=True
            ).count()
            
            user_stats.append({
                'user': user,
                'completed': completed,
                'total': total_modules,
                'phishing_correct': phishing_correct,
                'phishing_total': phishing_total
            })
    
    return render_template('admin.html', user_stats=user_stats)

def init_db():
    with app.app_context():
        db.create_all()
        
        # Create admin user if doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@securitytraining.local',
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
        
        # Add sample modules if none exist
        if Module.query.count() == 0:
            modules_data = [
                {
                    'title': 'Phishing Basics',
                    'description': 'Learn to identify and avoid phishing attacks',
                    'content': '''
                    <h3>What is Phishing?</h3>
                    <p>Phishing is a cybercrime where attackers impersonate legitimate organizations to steal sensitive information like passwords, credit card numbers, or personal data.</p>
                    
                    <h3>Common Red Flags</h3>
                    <ul>
                        <li><strong>Urgent or threatening language</strong> - "Act now or your account will be closed!"</li>
                        <li><strong>Suspicious sender addresses</strong> - Look closely at the email domain</li>
                        <li><strong>Generic greetings</strong> - "Dear Customer" instead of your name</li>
                        <li><strong>Spelling and grammar errors</strong> - Professional companies proofread</li>
                        <li><strong>Suspicious links</strong> - Hover over links to see the real destination</li>
                        <li><strong>Unexpected attachments</strong> - Don't open files from unknown sources</li>
                    </ul>
                    
                    <h3>What To Do</h3>
                    <p>If you receive a suspicious email:</p>
                    <ol>
                        <li>Don't click any links or download attachments</li>
                        <li>Report it to your IT/security team</li>
                        <li>Delete the email</li>
                        <li>If you clicked a link, change your password immediately</li>
                    </ol>
                    ''',
                    'quiz_questions': [
                        {
                            'question': 'What should you do if you receive an email asking you to urgently verify your account?',
                            'options': ['Click the link immediately', 'Forward it to friends', 'Report it to IT/security', 'Reply with your password'],
                            'correct': 2
                        },
                        {
                            'question': 'Which of these is a red flag in an email?',
                            'options': ['Professional formatting', 'Personalized greeting with your name', 'Urgent threats about account closure', 'Clear company branding'],
                            'correct': 2
                        },
                        {
                            'question': 'Before clicking a link, you should:',
                            'options': ['Click it to see where it goes', 'Hover over it to check the URL', 'Forward the email to verify', 'Always trust links in emails'],
                            'correct': 1
                        }
                    ]
                },
                {
                    'title': 'Password Security',
                    'description': 'Create and manage strong, secure passwords',
                    'content': '''
                    <h3>Why Password Security Matters</h3>
                    <p>Your password is often the only thing standing between attackers and your sensitive data. Weak passwords are easy to crack and can lead to devastating breaches.</p>
                    
                    <h3>Creating Strong Passwords</h3>
                    <ul>
                        <li><strong>Length matters</strong> - Use at least 12-16 characters</li>
                        <li><strong>Mix it up</strong> - Combine uppercase, lowercase, numbers, and symbols</li>
                        <li><strong>Avoid common patterns</strong> - No "Password123" or "qwerty"</li>
                        <li><strong>Don't use personal info</strong> - No birthdays, names, or addresses</li>
                        <li><strong>Use unique passwords</strong> - Different password for each account</li>
                    </ul>
                    
                    <h3>Password Managers</h3>
                    <p>Consider using a password manager like:</p>
                    <ul>
                        <li>1Password</li>
                        <li>LastPass</li>
                        <li>Bitwarden</li>
                        <li>KeePass</li>
                    </ul>
                    <p>These tools generate and store strong passwords securely, so you only need to remember one master password.</p>
                    
                    <h3>Two-Factor Authentication (2FA)</h3>
                    <p>Always enable 2FA when available. This adds an extra layer of security beyond your password.</p>
                    ''',
                    'quiz_questions': [
                        {
                            'question': 'What is the minimum recommended password length?',
                            'options': ['6 characters', '8 characters', '12-16 characters', '20 characters'],
                            'correct': 2
                        },
                        {
                            'question': 'Which password is strongest?',
                            'options': ['password123', 'MyBirthday1990!', 'Tr0ub4dor&3', 'correct-horse-battery-staple-2024!'],
                            'correct': 3
                        },
                        {
                            'question': 'What is the main benefit of two-factor authentication?',
                            'options': ['Makes passwords unnecessary', 'Requires something you know AND something you have', 'Automatically changes your password', 'Allows password sharing'],
                            'correct': 1
                        }
                    ]
                },
                {
                    'title': 'Social Engineering',
                    'description': 'Recognize and defend against manipulation tactics',
                    'content': '''
                    <h3>What is Social Engineering?</h3>
                    <p>Social engineering is the art of manipulating people into divulging confidential information or performing actions that compromise security. It exploits human psychology rather than technical vulnerabilities.</p>
                    
                    <h3>Common Tactics</h3>
                    <ul>
                        <li><strong>Pretexting</strong> - Creating a false scenario to steal information</li>
                        <li><strong>Baiting</strong> - Offering something enticing (free USB drive, gift card)</li>
                        <li><strong>Tailgating</strong> - Following authorized personnel into restricted areas</li>
                        <li><strong>Quid Pro Quo</strong> - Offering a service in exchange for information</li>
                        <li><strong>Authority</strong> - Impersonating someone in power (CEO, IT support)</li>
                        <li><strong>Urgency</strong> - Creating false time pressure to bypass scrutiny</li>
                    </ul>
                    
                    <h3>Defense Strategies</h3>
                    <ol>
                        <li><strong>Verify identities</strong> - Call back using official numbers</li>
                        <li><strong>Question unusual requests</strong> - Especially for sensitive information</li>
                        <li><strong>Follow procedures</strong> - Don't let anyone pressure you to bypass policy</li>
                        <li><strong>Report suspicious behavior</strong> - Alert security immediately</li>
                        <li><strong>Secure physical access</strong> - Don't hold doors open for strangers</li>
                    </ol>
                    
                    <h3>Real-World Example</h3>
                    <p>An attacker calls pretending to be from IT support, claiming there's an urgent security issue with your account. They ask for your password to "fix" it. This is social engineering - real IT will NEVER ask for your password.</p>
                    ''',
                    'quiz_questions': [
                        {
                            'question': 'Someone calls claiming to be from IT and asks for your password. What should you do?',
                            'options': ['Give them the password', 'Hang up and call IT directly using the official number', 'Ask them to email you instead', 'Give them a fake password'],
                            'correct': 1
                        },
                        {
                            'question': 'What is "tailgating" in security terms?',
                            'options': ['Following too closely while driving', 'Following someone into a secure area without proper authorization', 'Monitoring someone\'s computer screen', 'Copying someone\'s behavior'],
                            'correct': 1
                        },
                        {
                            'question': 'Why do social engineers use urgency as a tactic?',
                            'options': ['They are actually in a hurry', 'To pressure victims into acting without thinking', 'Because it\'s more polite', 'To save time'],
                            'correct': 1
                        }
                    ]
                }
            ]
            
            for module_data in modules_data:
                module = Module(**module_data)
                db.session.add(module)
        
        # Add phishing scenarios if none exist
        if PhishingScenario.query.count() == 0:
            scenarios = [
                {
                    'title': 'Urgent Account Verification',
                    'from_email': 'security-alert@bankofameriсa.com',
                    'subject': 'URGENT: Verify Your Account Within 24 Hours',
                    'body': '''Dear Valued Customer,

We have detected unusual activity on your account. For your security, we need you to verify your identity immediately.

Click here to verify your account: http://bankofamerica-secure-login.tk/verify

If you do not verify within 24 hours, your account will be permanently suspended.

Sincerely,
Bank of America Security Team''',
                    'red_flags': [
                        'Suspicious sender domain (notice the Cyrillic "с" in "americа")',
                        'Creates urgency with 24-hour deadline',
                        'Generic greeting instead of your name',
                        'Suspicious link domain (.tk is a red flag)',
                        'Threatens account suspension',
                        'No legitimate bank asks you to verify via email link'
                    ],
                    'difficulty': 'Easy'
                },
                {
                    'title': 'Package Delivery Notice',
                    'from_email': 'deliveries@fedex-tracking.net',
                    'subject': 'Your Package Couldn\'t Be Delivered',
                    'body': '''Hello,

We attempted to deliver your package today but no one was home.

Tracking Number: FDX9284756103

To reschedule delivery, please download and print the attached shipping label.

Attachment: FedEx_Shipping_Label_9284756103.pdf.exe

Thank you,
FedEx Customer Service''',
                    'red_flags': [
                        'Sender domain is not official FedEx domain',
                        'Unexpected package notification',
                        'Suspicious file extension (.pdf.exe is trying to hide as PDF)',
                        'Asks you to open an attachment',
                        'Generic greeting',
                        'Real FedEx tracking can be verified on their website'
                    ],
                    'difficulty': 'Medium'
                },
                {
                    'title': 'CEO Urgent Request',
                    'from_email': 'jennifer.smith@company-internal.com',
                    'subject': 'RE: Urgent - Wire Transfer Needed Today',
                    'body': '''Hi,

I'm in meetings all day but need you to process an urgent wire transfer to a new vendor. The details are below:

Account: 4582-9173-2847
Routing: 021000021  
Amount: $45,000
Vendor: Strategic Consulting Partners LLC

Please process this ASAP before 3 PM. I'll be unavailable by phone.

Thanks,
Jennifer Smith
CEO''',
                    'red_flags': [
                        'Unusual financial request via email',
                        'Creates urgency and time pressure',
                        'Claims to be unavailable for verification',
                        'Requests wire transfer to unknown vendor',
                        'Doesn\'t follow normal approval procedures',
                        'Should be verified through alternate communication channel'
                    ],
                    'difficulty': 'Hard'
                },
                {
                    'title': 'IT System Upgrade',
                    'from_email': 'it-support@company.com',
                    'subject': 'Required: Office 365 Password Update',
                    'body': '''Dear Employee,

As part of our system security upgrade, all employees must update their Office 365 credentials by end of day.

Click here to update your password: https://office365-login-portal.com/update

Your current credentials will expire at 5:00 PM today if not updated.

Thank you for your cooperation.

IT Support Team
Extension: 5555''',
                    'red_flags': [
                        'Legitimate IT never asks for password via email link',
                        'External URL pretending to be Office 365',
                        'Creates false urgency with deadline',
                        'IT would communicate through official channels',
                        'Real password changes happen through official portals',
                        'No specific IT person named'
                    ],
                    'difficulty': 'Medium'
                }
            ]
            
            for scenario_data in scenarios:
                scenario = PhishingScenario(**scenario_data)
                db.session.add(scenario)
        
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
