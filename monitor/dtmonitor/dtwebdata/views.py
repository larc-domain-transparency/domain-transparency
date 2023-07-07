import sys
sys.path.append('/local/home/hyper/domain-transparency/domain-transparency/monitor')

from django.shortcuts import render
from dtextract.extract import test
from django.http import HttpResponseRedirect
from django.contrib import messages
from dtwebdata.forms import DomainSearchForm
from dtwebdata.models import Domains

# Create your views here.
def monitor(request) :
    return render(request, 'monitor.html')

def getdomaindata(request): 
    if request.method == 'POST':
        form = DomainSearchForm(request.POST)
        if form.is_valid():
            domain_name = form.cleaned_data['domain_name']
            print(domain_name)
            messages.success(request, "Dados coletados com sucesso!")

            # if not voo:
            #     messages.error(request, "Código de voo inválido, voo não deletado.")
            # else:
            #     voo.delete()
            #     messages.success(request, "Voo deletado com sucesso.")
            return HttpResponseRedirect('/')
        return HttpResponseRedirect('/')
    else:
        return HttpResponseRedirect('/')

