# Generated by Django 5.1.4 on 2024-12-14 09:17

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='transaction',
            name='transaction_type',
        ),
    ]
