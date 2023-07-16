from django.contrib import admin
from .models import Appointment, CustomBusinessUser, Service

# Register your models here.
admin.site.register(Appointment)
admin.site.register(CustomBusinessUser)
admin.site.register(Service)
