from django import forms

from .models import Tickets


class RegisterForm(forms.Form):
	email = forms.CharField(max_length=255)
	password = forms.CharField(max_length=255, widget=forms.PasswordInput)


class LoginForm(forms.Form):
	email = forms.CharField(max_length=255)
	password = forms.CharField(max_length=255, widget=forms.PasswordInput)


class TicketForm(forms.Form):
	title = forms.CharField(max_length=255)
	description = forms.CharField(widget=forms.Textarea)
	severity = forms.ChoiceField(choices=Tickets.SEVERITY_CHOICES)
	status = forms.ChoiceField(choices=Tickets.STATUS_CHOICES)