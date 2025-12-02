🔐 Password Management System

A secure Flask-based web application to store, encrypt, and manage user credentials.
This system uses Flask, SQLAlchemy, Cryptography, and Bcrypt for strong encryption and safe storage.

🚀 Features

User registration & login

AES-encrypted password storage

Password generator

Add / view / delete saved credentials

Responsive UI

Session-based authentication

📂 Project Structure
Password_management_system/
│
├── app.py
├── database/
├── static/
├── templates/
├── instance/
├── app/
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore

🛠️ How to Run This Project

You can run this project either in the VS Code Terminal or in Windows CMD.
Both terminals use the same commands.

1️⃣ Clone the repository
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

2️⃣ Create a virtual environment
python -m venv venv

3️⃣ Activate the virtual environment
✔️ If using VS Code Terminal (PowerShell)
.\venv\Scripts\activate

✔️ If using Windows CMD
venv\Scripts\activate


After activation, your terminal will look like:

(venv) D:\Password_management_system>

4️⃣ Install dependencies

If you have a requirements file:

python -m pip install -r requirements.txt


Or install manually:

python -m pip install flask flask_sqlalchemy flask-bcrypt cryptography

5️⃣ Run the application
python app.py


The server will start at:

👉 http://127.0.0.1:5000

Open this link in your browser.

✔️ You're ready to use the Password Manager!
⚠️ Important Notes

The venv folder should NOT be pushed to GitHub (your .gitignore covers this).

This project runs in debug mode and is not meant for production.

The database is stored inside the instance folder.

📝 License

This project is licensed under the MIT License.
