# Generated by Django 2.2 on 2022-03-03 08:21

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0009_resume_portfoliourl'),
    ]

    operations = [
        migrations.AddField(
            model_name='resume',
            name='Data',
            field=models.ForeignKey(default='1', on_delete=django.db.models.deletion.CASCADE, to='accounts.User'),
        ),
    ]
