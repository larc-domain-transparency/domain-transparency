from django.db import models

# Create your models here.
class Domains(models.Model) :
    id = models.IntegerField(primary_key=True)
    domain_entry = models.CharField(max_length=1000, null=False)
    leaf_input = models.CharField(max_length=1000, null=False)
    extra_data = models.CharField(max_length=1000, null=False)

    class Meta:
        db_table = 'domain_info'