
from django.contrib import admin
from .models import Doctor, File, Request  # Import your models
from .models import ActivityLog
admin.site.register(Doctor)       # Show all doctors in the admin panel
admin.site.register(File)         # Show all uploaded files
admin.site.register(Request)  # Show all file requests
admin.site.register(ActivityLog)
