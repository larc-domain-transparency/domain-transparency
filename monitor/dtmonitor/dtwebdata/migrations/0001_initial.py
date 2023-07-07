# Generated by Django 4.2.2 on 2023-07-07 14:10

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Domains',
            fields=[
                ('id', models.IntegerField(primary_key=True, serialize=False)),
                ('domain_entry', models.CharField(max_length=1000)),
                ('leaf_input', models.CharField(max_length=1000)),
                ('extra_data', models.CharField(max_length=1000)),
            ],
            options={
                'db_table': 'domain_info',
            },
        ),
    ]
