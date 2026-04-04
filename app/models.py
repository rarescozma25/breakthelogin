from django.db import models


class Users(models.Model):
	ROLE_ANALYST = "ANALYST"
	ROLE_MANAGER = "MANAGER"
	ROLE_CHOICES = [
		(ROLE_ANALYST, "ANALYST"),
		(ROLE_MANAGER, "MANAGER"),
	]

	id = models.AutoField(primary_key=True)
	email = models.CharField(max_length=255, unique=True)
	password_hash = models.CharField(max_length=255)
	role = models.CharField(max_length=20, choices=ROLE_CHOICES)
	created_at = models.DateTimeField(auto_now_add=True)
	locked = models.BooleanField(default=False)
	failed_attempts = models.IntegerField(default=0)
	last_failed_login = models.DateTimeField(null=True, blank=True)
	reset_token = models.CharField(max_length=128, null=True, blank=True)
	reset_token_expiry = models.DateTimeField(null=True, blank=True)

	class Meta:
		db_table = "users"


class Tickets(models.Model):
	SEVERITY_LOW = "LOW"
	SEVERITY_MED = "MED"
	SEVERITY_HIGH = "HIGH"
	SEVERITY_CHOICES = [
		(SEVERITY_LOW, "LOW"),
		(SEVERITY_MED, "MED"),
		(SEVERITY_HIGH, "HIGH"),
	]

	STATUS_OPEN = "OPEN"
	STATUS_IN_PROGRESS = "IN_PROGRESS"
	STATUS_RESOLVED = "RESOLVED"
	STATUS_CHOICES = [
		(STATUS_OPEN, "OPEN"),
		(STATUS_IN_PROGRESS, "IN_PROGRESS"),
		(STATUS_RESOLVED, "RESOLVED"),
	]

	id = models.AutoField(primary_key=True)
	title = models.CharField(max_length=255)
	description = models.TextField()
	severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
	status = models.CharField(max_length=20, choices=STATUS_CHOICES)
	owner_id = models.ForeignKey(
		Users,
		on_delete=models.CASCADE, 
		db_column="owner_id",
		related_name="tickets",
	)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta: # specifica numele tabelei in baza de date
		db_table = "tickets"


class AuditLogs(models.Model):
	id = models.AutoField(primary_key=True)
	user_id = models.ForeignKey(
		Users,
		on_delete=models.CASCADE, #daca un utilizator este sters, stergem si logurile lui
		db_column="user_id",
		related_name="audit_logs",
  		null=True, blank=True	
	)
	action = models.CharField(max_length=100)
	resource = models.CharField(max_length=100)
	resource_id = models.CharField(max_length=255)
	timestamp = models.DateTimeField(auto_now_add=True)
	ip_address = models.CharField(max_length=255)

	class Meta:
		db_table = "audit_logs"
