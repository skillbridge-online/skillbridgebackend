import random
from django.core.mail import send_mail
from django.conf import settings
from django.core.cache import cache

def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    """Send OTP to the user's email"""
    subject = "Your OTP Code"
    message = f"Your OTP code is {otp}. It will expire in 10 minutes."
    sender = settings.EMAIL_HOST_USER
    recipient_list = [email]

    send_mail(subject, message, sender, recipient_list)
