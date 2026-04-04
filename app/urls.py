from django.urls import path

from . import views


urlpatterns = [
	path("register", views.register_view, name="register"),
	path("login", views.login_view, name="login"),
	path("logout", views.logout_view, name="logout"),
	path("forgot-password", views.forgot_password_view, name="forgot_password"),
	path("home", views.home_view, name="home"),
	path("audit-logs", views.audit_logs_view, name="audit_logs"),
	path("tickets/create", views.create_ticket_view, name="create_ticket"),
	path("tickets/<int:id>", views.view_ticket_view, name="view_ticket"),
	path("tickets/<int:id>/edit", views.edit_ticket_view, name="edit_ticket"),
]
