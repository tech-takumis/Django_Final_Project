# Generated by Django 5.1.4 on 2024-12-24 13:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_remove_bankaccount_balance_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='bankaccount',
            name='balance',
            field=models.TextField(default=0),
            preserve_default=False,
        ),
    ]
