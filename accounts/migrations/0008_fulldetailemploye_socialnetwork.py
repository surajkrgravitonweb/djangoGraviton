# Generated by Django 2.2 on 2022-03-03 07:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_auto_20220223_1057'),
    ]

    operations = [
        migrations.AddField(
            model_name='fulldetailemploye',
            name='socialNetwork',
            field=models.CharField(default='google.com', max_length=121),
        ),
    ]
