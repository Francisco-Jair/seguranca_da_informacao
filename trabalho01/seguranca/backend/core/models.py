from django.db import models


class Chaves(models.Model):
    chavePublica = models.CharField("Chave Pública", max_length=100000)
    chavePrivada = models.CharField("Chave Privada", max_length=100000)
    assinatura = models.CharField(max_length=100000)
    sha = models.CharField(max_length=10)