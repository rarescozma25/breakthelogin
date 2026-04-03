import re
import bcrypt
from datetime import timedelta
from django.utils import timezone

from django.shortcuts import redirect, render

from .forms import LoginForm, RegisterForm, TicketForm
from .models import AuditLogs, Tickets, Users
#import csrf_exempt for testing purposes only, do not use in production
from django.views.decorators.csrf import csrf_exempt


def hash_password(password):
	salt = bcrypt.gensalt() # salt for hashing
	hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
	return hashed.decode('utf-8')


def get_client_ip(request):
	x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
	if x_forwarded_for:
		return x_forwarded_for.split(',')[0].strip()
	return request.META.get('REMOTE_ADDR', 'unknown')


def is_strong_password(password):

	if not password or len(password) < 10:
		return False


	if not re.search(r"[A-Z]", password):
		return False
	if not re.search(r"[a-z]", password):
		return False
	if not re.search(r"[0-9]", password):
		return False
	if not re.search(r"[^A-Za-z0-9]", password):
		return False

	return True

#@csrf_exempt
def register_view(request):
	if request.method == "POST":
		form = RegisterForm(request.POST)
		if not form.is_valid():
			return render(request, "register.html", {"error": "Email and password are required"})

		email = form.cleaned_data["email"]
		password = form.cleaned_data["password"]

		if not is_strong_password(password):
			return render(
				request,
				"register.html",
				{
					"form": form,
					"error": "Password must be at least 10 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character.",
				},
			)

		if Users.objects.filter(email=email).exists():
			return render(request, "register.html", {"form": form, "error": "User already exists"})
		# hash password
		hashed_password = hash_password(password)
		Users.objects.create(
			email=email,
			password_hash=hashed_password,
			role=Users.ROLE_ANALYST,
		)
		return redirect("login")

	form = RegisterForm()
	return render(request, "register.html", {"form": form})

#@csrf_exempt
def login_view(request):
	if request.method == "POST":
		form = LoginForm(request.POST)

		if not form.is_valid():
			return render(request, "login.html", {"error": "Invalid credentials"})

		email = form.cleaned_data["email"]
		password = form.cleaned_data["password"]
		ip_address = get_client_ip(request)

		try:
			user = Users.objects.get(email=email)
		except Users.DoesNotExist:
			AuditLogs.objects.create(
				user_id_id=None,
				action="LOGIN_FAILED_UNKNOWN_USER",
				resource="auth",
				resource_id="unknown",
				ip_address=ip_address,
			)
			return render(request, "login.html", {
				"form": form,
				"error": "Invalid credentials"
			})

		now = timezone.now()

		# check if account is locked
		if user.locked:
			lock_expiry = user.last_failed_login + timedelta(minutes=3)

			if now < lock_expiry:
				AuditLogs.objects.create(
					user_id_id=user.id,
					action="LOGIN_FAILED",
					resource="auth",
					resource_id=str(user.id),
					ip_address=ip_address,
				)
				remaining_lock_time = int((lock_expiry - now).total_seconds() // 60)
				return render(request, "login.html", {
					"form": form,
					"error": f"Your account is locked for {remaining_lock_time} more minutes due to multiple failed login attempts."
				}, status=429)

			# unlock account after lockout period
			user.locked = False
			user.failed_attempts = 0
			user.last_failed_login = None
			user.save(update_fields=["locked", "failed_attempts", "last_failed_login"])

		# verify password
		if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
			user.failed_attempts += 1
			user.last_failed_login = now

			if user.failed_attempts >= 5:
				user.locked = True
				AuditLogs.objects.create(
					user_id_id=user.id,
					action="ACCOUNT_LOCKED",
					resource="auth",
					resource_id=str(user.id),
					ip_address=ip_address,
				)
				user.save(update_fields=["failed_attempts", "last_failed_login", "locked"])

				return render(request, "login.html", {
					"form": form,
					"error": "Invalid credentials"
				}, status=429)

			user.save(update_fields=["failed_attempts", "last_failed_login"])

			AuditLogs.objects.create(
				user_id_id=user.id,
				action="LOGIN_FAILED",
				resource="auth",
				resource_id=str(user.id),
				ip_address=ip_address,
			)

			return render(request, "login.html", {
				"form": form,
				"error": "Invalid credentials"
			})

		# Start a fresh session so the old session ID cannot be reused.
		request.session.flush()

		# success
		user.failed_attempts = 0
		user.last_failed_login = None
		user.locked = False
		user.save(update_fields=["failed_attempts", "last_failed_login", "locked"])

		AuditLogs.objects.create(
			user_id_id=user.id,
			action="LOGIN_SUCCESS",
			resource="auth",
			resource_id=str(user.id),
			ip_address=ip_address,
		)

		request.session["user_id"] = user.id
		request.session["logged_in"] = True

		return redirect("home")

	return render(request, "login.html", {"form": LoginForm()})




def logout_view(request):
    # Flush the session so authentication data and the session ID are invalidated.
    request.session.flush()
    return redirect("login")


def forgot_password_view(request):
	error = ""
	message = ""
	token = request.GET.get("token", "")

	if token:
		message = "Enter a new password for your account"
		try:
			user = Users.objects.get(email=token)
		except Users.DoesNotExist:
			user = None

		if request.method == "POST":
			new_password = request.POST.get("new_password", "")
			if user:
				if not is_strong_password(new_password):
					error = "Password must be at least 10 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character."
					return render(
						request,
						"forgot_password.html",
						{
							"token": token,
							"message": message,
							"error": error,
						},
					)
				hashed_password = hash_password(new_password)
				user.password_hash = hashed_password
				user.save()
				return redirect("login")
			else:
				error = "Invalid token"

		return render(
			request,
			"forgot_password.html",
			{
				"token": token,
				"message": message,
				"error": error,
			},
		)

	if request.method == "POST":
		email = request.POST.get("email", "")
		try:
			Users.objects.get(email=email)
		except Users.DoesNotExist:
			error = "User not found"
		else:
			token = email
			return redirect(f"/forgot-password?token={token}")

	return render(
		request,
		"forgot_password.html",
		{
			"token": token,
			"message": message,
			"error": error,
		},
	)


def home_view(request):
	user_id = request.session.get("user_id")
	if not user_id:
		return redirect("login")

	try:
		current_user = Users.objects.get(id=user_id)
	except Users.DoesNotExist:
		return redirect("login")

	if current_user.role == Users.ROLE_MANAGER:
		tickets = Tickets.objects.all().order_by("-id")
	else:
		tickets = Tickets.objects.filter(owner_id=current_user).order_by("-id")
	return render(
		request,
		"home.html",
		{
			"current_user": current_user,
			"tickets": tickets,
		},
	)


def create_ticket_view(request):
	user_id = request.session.get("user_id")
	if not user_id:
		return redirect("login")

	if request.method == "POST":
		form = TicketForm(request.POST)
		if not form.is_valid():
			return render(request, "create_ticket.html", {"form": form, "error": "Invalid ticket data"})

		title = form.cleaned_data["title"]
		description = form.cleaned_data["description"]
		severity = form.cleaned_data["severity"]
		status = form.cleaned_data["status"]

		owner = Users.objects.get(id=user_id)
		ticket = Tickets.objects.create(
			title=title,
			description=description,
			severity=severity,
			status=status,
			owner_id=owner,
		)

		AuditLogs.objects.create(
			user_id=owner,
			action="CREATE_TICKET",
			resource="ticket",
			resource_id=str(ticket.id),
			ip_address=request.META.get("REMOTE_ADDR", ""),
		)
		return redirect("home")

	form = TicketForm()
	return render(request, "create_ticket.html", {"form": form})


def view_ticket_view(request, id):
	user_id = request.session.get("user_id")
	if not user_id:
		return redirect("login")

	ticket = Tickets.objects.get(id=id)
	return render(request, "view_ticket.html", {"ticket": ticket})


def edit_ticket_view(request, id):
	user_id = request.session.get("user_id")
	if not user_id:
		return redirect("login")

	ticket = Tickets.objects.get(id=id)

	if request.method == "POST":
		form = TicketForm(request.POST)
		if not form.is_valid():
			return render(request, "edit_ticket.html", {"ticket": ticket, "form": form, "error": "Invalid ticket data"})

		ticket.title = form.cleaned_data["title"]
		ticket.description = form.cleaned_data["description"]
		ticket.severity = form.cleaned_data["severity"]
		ticket.status = form.cleaned_data["status"]
		ticket.save()

		user = Users.objects.get(id=user_id)
		AuditLogs.objects.create(
			user_id=user,
			action="EDIT_TICKET",
			resource="ticket",
			resource_id=str(ticket.id),
			ip_address=request.META.get("REMOTE_ADDR", ""),
		)
		return redirect("view_ticket", id=ticket.id)

	form = TicketForm(
		initial={
			"title": ticket.title,
			"description": ticket.description,
			"severity": ticket.severity,
			"status": ticket.status,
		}
	)
	return render(request, "edit_ticket.html", {"ticket": ticket, "form": form})
