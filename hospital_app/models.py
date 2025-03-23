from django.db import models
from django.contrib.auth.models import User
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from django.contrib.auth.models import User

class Doctor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=50 , unique=True)
    mobile = models.CharField(max_length=10)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')])
    department = models.CharField(max_length=50)
    designation = models.CharField(max_length=100)
    address = models.TextField()
    country = models.CharField(max_length=50)
    container_name = models.CharField(max_length=100, unique=True, null=True, blank=True)  # New field
    
    def __str__(self):
        return f"{self.user.username} - {self.designation}"

class File(models.Model):
    filename = models.CharField(max_length=255)
    sender = models.ForeignKey(User, related_name='sent_files', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_files', on_delete=models.CASCADE)
    encryption_key = models.BinaryField()

    def __str__(self):
        return self.filename
class ActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.TextField()  # Stores what the doctor did
    timestamp = models.DateTimeField(auto_now_add=True)  # Stores when it happened

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"
    
class Request(models.Model):
    filename = models.CharField(max_length=255)  # ✅ Store filename
    sender = models.ForeignKey(User, related_name='requests_received', on_delete=models.CASCADE)  # ✅ Store sender
    requester = models.ForeignKey(User, related_name='requests_sent', on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=[('Pending', 'Pending'), ('Approved', 'Approved')], default='Pending')

    def __str__(self):
        return f"Request for {self.file.filename} from {self.requester.username} - {self.status}"

class DoctorKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    private_key = models.BinaryField()
    public_key = models.BinaryField()

    def generate_keys(self):
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        self.private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.save()

    def __str__(self):
        return f"Keys for {self.user.username}"