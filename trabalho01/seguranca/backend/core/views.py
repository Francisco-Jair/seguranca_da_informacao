from Crypto.Signature import pkcs1_15
from django.shortcuts import render, redirect
from django.urls import reverse
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5, SHA224
from .models import Chaves

  

def index(request):

    chaves = list(Chaves.objects.all())

    if  chaves == []:
        chaveprivada = ""
        chavepublica = ""
        assinatura = ""
        sha = ""
    else:
        key = chaves[-1]
        chaveprivada = key.chavePrivada[:1000]
        chavepublica = key.chavePublica
        assinatura = key.assinatura
        sha = key.sha

    context = {
        "title" : "Assinador de Texto",
        "chaveprivada" : chaveprivada,
        "chavepublica" : chavepublica,
        "assinatura" : assinatura,
        "sha" : sha
    }

    return render(request, "core/index.html", context)


def gerar_chaves(request):

    if request.method == "POST":

        if len(list(Chaves.objects.all())) == 0:
            key = Chaves()
        else:
            key = Chaves.objects.all()[-1]

        chave = RSA.generate(2048)
        key.chavePrivada = chave.export_key().hex()
        key.chavePublica = chave.publickey().export_key().hex()
        key.save()
        
        #Salvando chave Privada
        #f = open('keyfile.pem', 'wb')
        #f.write(chave.exportKey('PEM'))
        #f.close()

    return redirect(reverse("home"))


def assinar(request):

    if request.method == "POST":
        tipoSha = request.POST.get("exampleFormControlSelect1")
        texto = request.POST.get("exampleFormControlTextarea12")

        key = list(Chaves.objects.all())[-1]

        chavePrivada = RSA.import_key(bytes.fromhex(key.chavePrivada))
        #f = open('keyfile.pem', 'rb')
        #chavePrivada = RSA.importKey(f.read())
        valorCifraTexto = generateSha(tipoSha, texto)

        assinatura = pkcs1_15.new(chavePrivada).sign(valorCifraTexto)
        # certeza = assinatura.sign(valorCifraTexto)
        # assinatura = hmac.new(chavePrivada, valorCifraTexto)
        
        key.sha = tipoSha
        key.assinatura = assinatura.hex()
        key.save()

    return redirect(reverse("home"))


def generateSha(tipo, text):

    hashValue = ""

    if "SHA256" == tipo:
        hashValue = convertSha256()
    elif "SHA384" == tipo:
        hashValue = convertSha384()
    elif "SHA224" == tipo:
        hashValue = convertSha224()
    elif "SHA512" == tipo:
        hashValue = convertSha512()
    elif "SHA1" == tipo:
        hashValue = convertSha1()
    elif "MD5" == tipo:
        hashValue = convertMd5()
    
    hashValue.update(text.encode("utf8"))
    return hashValue


def convertSha256():
    return SHA256.new()


def convertSha384():
    return SHA384.new()


def convertSha224():
    return SHA224.new()


def convertSha512():
    return SHA512.new()


def convertSha1():
    return SHA.new()


def convertMd5():
    return MD5.new()


def verificar(request):
    tipo = 0
    status = None

    chaves = list(Chaves.objects.all())
    if chaves != []:
        chaves[-1].delete()
        # Excluir chave privada

    if request.method == "POST":
        try:
            chavePublica = bytes.fromhex(request.POST.get("exampleFormControlTextarea1"))
            texto = request.POST.get("exampleFormControlTextarea12")
            assina = bytes.fromhex(request.POST.get("exampleFormControlTextarea3"))
            tipoSha = request.POST.get("exampleFormControlSelect1")

            chave = RSA.import_key(chavePublica)
            t = generateSha(tipoSha, texto)
            # pkcs1_15.new(chave).verify(t, assina)
        
            pkcs1_15.new(chave).verify(t, assina)
            tipo = 1
            status = True
        except (ValueError, TypeError):
            tipo = 2
            status = False


    print(status)
    print(tipo)
    context = {
        "title" : "Verificar Assinatura",
        "tipo" : tipo,
        "status" : status,
        # "chavePublica" : chavePublica
    }

    return render(request, "core/verificar.html", context)

