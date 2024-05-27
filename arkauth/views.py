from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError

from .utils import TokenGenerator, generate_token

from django.core.mail import send_mail, EmailMultiAlternatives
from django.core.mail import BadHeaderError, send_mail
from django.core import mail
from django.conf import settings
from django.core.mail.message import EmailMessage

import threading

from django.contrib.auth.tokens import PasswordResetTokenGenerator


class EmailThread(threading.Thread):
    def __init__(self, email_message):
        super().__init__()  # Initialize the thread object
        self.email_message = email_message

    def run(self):
        self.email_message.send()


def signup(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        
        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'auth/signup.html')

        try:
            if User.objects.get(username=email):
                messages.warning(request, "Email is already taken")
                return render(request, 'auth/signup.html')
        except User.DoesNotExist:
            pass

        user = User.objects.create_user(username=email, email=email, password=password)
        user.is_active = True
        user.save()
        
        current_site = get_current_site(request)
        email_subject = "Activate Your Account"
        message = render_to_string('auth/activate.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })
        
        email_message = EmailMessage(email_subject, message, to=[email])
        EmailThread(email_message).start()
        
        messages.info(request, "Activate your account by clicking the link sent to your email.")
        return redirect('/arkauth/login/')
    
    return render(request, 'auth/signup.html')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Account Activated Successfully")
            return redirect('/arkauth/login')
        return render(request, 'auth/login.html')


def handlelogin(request):
    if request.method == "POST":
        username = request.POST['email']
        userpassword = request.POST['pass1']
        myuser = authenticate(username=username, password=userpassword)

        if myuser is not None:
            login(request, myuser)
            messages.success(request, "Login Success")
            return render(request, 'index.html')

        else:
            messages.error(request, "Invalid Password")
            return redirect('/arkauth/login')

    return render(request, 'auth/login.html')


def handlelogout(request):
    logout(request)
    messages.success(request, "Logout Success")
    return redirect('/arkauth/login')


class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'auth/request-reset-email.html')

    def post(self, request):
        email = request.POST['email']
        user = User.objects.filter(email=email)
        if user.exists():
            current_site = get_current_site(request)
            email_subject = '[Reset Your Password]'
            message = render_to_string('auth/reset-user-password.html', {
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])
            })
            email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
            EmailThread(email_message).start()
            messages.info(request, "We have sent you an email with instructions on how to reset the password.")
            return render(request, 'auth/request-reset-email.html')
        else:
            messages.error(request, "No user is associated with this email.")
            return render(request, 'auth/request-reset-email.html')



class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            "uidb64": uidb64,
            "token": token
        }
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password Reset Link is Invalid")
                return render(request, 'auth/request-reset-email.html')
        except DjangoUnicodeDecodeError:
            messages.error(request, "Invalid link")
            return render(request, 'auth/request-reset-email.html')
        return render(request, 'auth/set-new-password.html', context)

    def post(self, request, uidb64, token):
        context = {
            "uidb64": uidb64,
            "token": token
        }
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        
        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'auth/set-new-password.html', context)
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request, "Password Reset Success. Please login with your new password.")
            return redirect('/arkauth/login/')
        except DjangoUnicodeDecodeError:
            messages.error(request, "Something went wrong")
            return render(request, 'auth/set-new-password.html', context)