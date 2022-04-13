import hashlib
from django.shortcuts import render, redirect
from django.urls import reverse
from Crypto.PublicKey import RSA

 

def gerar_chaves(request):
    
    chave = RSA.generate(2048)
    private_key = chave.export_key().hex()
    public_key = chave.publickey().export_key().hex()

    context = {
        "chaveprivada" : private_key,
        "chavepublica" : public_key
    }

    return redirect(reverse("home"))
    # return render(request, "core/index.html", context)


def assinar(text):
    result = hashlib.sha256(text.encode())


def index(request):
    
    context = {
        "chaveprivada" : "",
        "chavepublica" : ""
    }

    return render(request, "core/index.html", context)