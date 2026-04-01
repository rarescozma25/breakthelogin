from django.shortcuts import redirect, render

from .forms import LoginForm, RegisterForm, TicketForm
from .models import AuditLogs, Tickets, Users


def register_view(request):
	if request.method == "POST":
		form = RegisterForm(request.POST)
		if not form.is_valid():
			return render(request, "register.html", {"error": "Email and password are required"})

		email = form.cleaned_data["email"]
		password = form.cleaned_data["password"]

		if Users.objects.filter(email=email).exists():
			return render(request, "register.html", {"form": form, "error": "User already exists"})

		Users.objects.create(
			email=email,
			password_hash=password,
			role=Users.ROLE_ANALYST,
		)
		return redirect("login")

	form = RegisterForm()
	return render(request, "register.html", {"form": form})


def login_view(request):
	if request.method == "POST":
		form = LoginForm(request.POST)
		if not form.is_valid():
			return render(request, "login.html", {"error": "Email and password are required"})

		email = form.cleaned_data["email"]
		password = form.cleaned_data["password"]

		try:
			user = Users.objects.get(email=email)
		except Users.DoesNotExist:
			return render(request, "login.html", {"form": form, "error": "User does not exist"})

		if user.password_hash != password:
			return render(request, "login.html", {"form": form, "error": "Wrong password"})

		request.session["user_id"] = user.id
		request.session["logged_in"] = True
		return redirect("home")

	form = LoginForm()
	return render(request, "login.html", {"form": form})


def logout_view(request):
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
				user.password_hash = new_password
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

	tickets = Tickets.objects.all().order_by("-id")
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
