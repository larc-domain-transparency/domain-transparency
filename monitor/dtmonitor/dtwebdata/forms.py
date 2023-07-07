from django import forms

class DomainSearchForm(forms.Form):
    domain_name = forms.CharField(label='Domain name', max_length=100)

