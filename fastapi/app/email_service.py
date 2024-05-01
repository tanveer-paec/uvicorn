# app/email_service.py

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_verification_email(email: str, verification_code: str):
    # Email configuration
    sender_email = "someonesail@hotmail.com"  # Replace with your email address
    sender_password = "sailsomeone1"   # Replace with your email password

    # Create message container
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "Verification Code"

    # Email body
    body = f"Your verification code is: {verification_code}"
    msg.attach(MIMEText(body, 'plain'))

    # Send the email
    try:
        with smtplib.SMTP('smtp.office365.com', 587) as smtp:
            smtp.starttls()
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)
        print("Verification email sent successfully!")
    except Exception as e:
        print(f"Error sending verification email: {e}")
