🩸 Blood Donation Request & Management System

A location-based blood donation management application using Flask and Telegram Bots. This project ensures that blood requests from patients are fulfilled efficiently by notifying nearby hospitals and donors, tracking donation progress, and updating dashboards based on real-time feedback.

.

🌟 Project Overview

-> When a patient requires blood, the system

-> Receives the blood request from the patient.

-> Sends notifications to nearby hospitals based on the patient’s location.

-> If the hospital has the required blood, it can accept or reject the request.

-> If the hospital cannot fulfill the request, notifications are sent to nearby donors.

-> Donors can accept the request, go to the hospital, and donate blood.

-> After donation, the patient provides feedback, which updates the donor’s progress in the dashboard.

-> The system continues to send notifications to other users if more requests are pending.

-> Patients can also check available donors and hospitals.

This ensures fast, efficient, and location-based blood donation using automated notifications via Telegram bots.

<img width="2000" height="990" alt="image" src="https://github.com/user-attachments/assets/b4d3bb54-2dd0-4c50-8262-67aefc610be8" />
 <img width="453" height="855" alt="image" src="https://github.com/user-attachments/assets/1cee742c-00c7-416c-b5dc-17a3b43986a9" />
<img width="535" height="919" alt="image" src="https://github.com/user-attachments/assets/25174c01-4048-484f-9081-81b2b9a772e2" />
<img width="501" height="752" alt="image" src="https://github.com/user-attachments/assets/c0982d8a-3be9-4d5c-b22a-f4be74d1746a" />
<img width="1246" height="402" alt="image" src="https://github.com/user-attachments/assets/41c459b5-111a-4b26-8454-7ef339f19fb5" />
<img width="1817" height="786" alt="image" src="https://github.com/user-attachments/assets/bf5ce83e-d82d-49e9-9455-dd0015d709d7" />
<img width="417" height="920" alt="image" src="https://github.com/user-attachments/assets/b056ac09-d31a-49c4-a52e-383b38dbd90a" />
<img width="401" height="921" alt="image" src="https://github.com/user-attachments/assets/b9a8c8c9-dc3f-44e1-9c2e-f6faf7825bde" />




🛠️ Features

-> Patient Blood Request Handling

-> Patients submit blood requests through the web app.

-> Requests are sent to hospitals and donors based on location.

-> Hospital Notifications & Acceptance

-> Hospitals receive requests and can accept/reject based on availability.

-> Donor Notifications & Tracking

-> Nearby donors are notified if hospitals cannot fulfill requests.

-> Donor activity and progress are tracked on dashboards.

-> Telegram Bot Integration

-> Automated notifications to hospitals, donors, and patients.

-> OTP verification for secure donor interactions.

-> Feedback & Progress Management

-> Patients can rate the donor experience.

-> Donor performance updates dynamically on dashboards.

-> Location-Based Matching

-> Requests are matched with hospitals and donors nearest to the patient’s location.

🛠️ Tech Stack

-> Backend: Python, Flask

-> Database: MongoDB Atlas

-> Bots: Telegram Bot API, python-telegram-bot

-> File Storage: Cloudinary (for uploads)

-> Authentication: bcrypt for secure password hashing

-> Frontend: HTML, CSS, Jinja2 templates

🚀 Setup Instructions

Create a .env file with:

BOT_TOKEN=<your_telegram_bot_token>
OTP_BOT_TOKEN=<your_otp_bot_token>
MONGODB_URI=<your_mongodb_atlas_uri>
CLOUDINARY_CLOUD_NAME=<cloud_name>
CLOUDINARY_API_KEY=<api_key>
CLOUDINARY_API_SECRET=<api_secret>
WEBHOOK_URL=<your_ngrok_or_production_url>/webhook

Access the web app at:

http://127.0.0.1:3000

📂 Project Structure
bloodbot/
├── main.py   # Flask app entry point

├── routes.py           # Flask routes & endpoints
├── db_utils.py         # MongoDB connection & helper functions
├── bot_handlers.py     # Telegram bot handlers
├── templates/          # HTML templates
│   ├── hospital_register.html
│   └── hospital_login.html
├── static/             # CSS & JS files
├── config.py           # Configurations & logging
└── requirements.txt    # Python dependencies

💡 Future Enhancements

-> Real-time donor availability map.
-> Dashboard analytics for hospital & donor performance.
-> Multi-language support for broader accessibility.
-> Emergency request prioritization and alerts.
