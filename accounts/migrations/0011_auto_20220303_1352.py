# Generated by Django 2.2 on 2022-03-03 08:22

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0010_resume_data'),
    ]

    operations = [
        migrations.AlterField(
            model_name='resume',
            name='Data',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='accounts.User'),
        ),
    ]
