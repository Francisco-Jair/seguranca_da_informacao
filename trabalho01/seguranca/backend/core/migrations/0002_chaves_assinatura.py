# Generated by Django 4.0.4 on 2022-04-14 22:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='chaves',
            name='assinatura',
            field=models.CharField(default=None, max_length=100000, verbose_name='Chave Pública'),
            preserve_default=False,
        ),
    ]
