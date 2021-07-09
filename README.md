# Advanced Flask 2-Factor Authenication System
A simple flask two factor authentication system that, along with your password requires a 6-digit pin from otp-based mobile authenticator app such as Microsoft Authenticator or Google Authenticator, or questions and share them with others to get an answer/opinion.
# Quick Start
- Clone this repo: `git clone https://github.com/BouncyBird/advanced-flask-2fa.git` or with the GitHub CLI: `gh repo clone BouncyBird/advanced-flask-2fa`
- Open that folder in a editor(VScode)
- Optionally create a virtual environment
- Install the required packages from the requirements.txt file: `pip install -r requirements.txt`
- Initialize the database with these commands:
  - `flask db init`
  - `flask db migrate`
  - `flask db upgrade`
- Run the app: `python app.py`
