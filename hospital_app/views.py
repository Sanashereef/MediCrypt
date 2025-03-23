from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import openstack
import json
import os
import base64
import secrets
import tempfile
import logging
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from .models import Doctor, DoctorKey, Request, File, ActivityLog
from .encryption import generate_dh_keys, derive_aes_key, encrypt_file

# OpenStack credentials (ideally from settings.py or environment variables)
OPENSTACK_AUTH_URL = os.getenv('OPENSTACK_AUTH_URL', 'http://127.0.0.1/identity')
OPENSTACK_PROJECT_NAME = os.getenv('OPENSTACK_PROJECT_NAME', 'admin')
OPENSTACK_USERNAME = os.getenv('OPENSTACK_USERNAME', 'admin')
OPENSTACK_PASSWORD = os.getenv('OPENSTACK_PASSWORD', 'user')
OPENSTACK_USER_DOMAIN_NAME = os.getenv('OPENSTACK_USER_DOMAIN_NAME', 'Default')
OPENSTACK_PROJECT_DOMAIN_NAME = os.getenv('OPENSTACK_PROJECT_DOMAIN_NAME', 'Default')
OPENSTACK_REGION_NAME = os.getenv('OPENSTACK_REGION_NAME', 'RegionOne')

logger = logging.getLogger(__name__)

# Utility Functions
def log_action(user, action_text):
    ActivityLog.objects.create(user=user, action=action_text)

def load_dh_private_key(pem_data):
    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())

def load_dh_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

# Views
def landing_page(request):
    return render(request, 'landing.html')

def received_requests(request):
    return render(request, 'received_requests.html')

@login_required
def view_profile(request):
    doctor = Doctor.objects.get(user_id=request.user.id)
    return render(request, 'profile.html', {'doctor': doctor})

@login_required
def requested_files(request):
    doctor_id = request.user.id
    requests = Request.objects.filter(sender_id=doctor_id).select_related('requester').order_by('-id')
    request_data = [
        {
            "id": req.id,
            "requester_name": Doctor.objects.filter(id=req.requester_id).first().username if Doctor.objects.filter(id=req.requester_id).exists() else "Unknown",
            "filename": req.filename,
            "status": req.status
        }
        for req in requests
    ]
    return render(request, 'requested_files.html', {'requests': request_data})

def logout_view(request):
    logout(request)
    return redirect('login')

class ContainerSecurityFunc:
    @staticmethod
    def connect_openstack():
        return openstack.connection.Connection(
            auth_url=OPENSTACK_AUTH_URL,
            project_name=OPENSTACK_PROJECT_NAME,
            username=OPENSTACK_USERNAME,
            password=OPENSTACK_PASSWORD,
            region_name=OPENSTACK_REGION_NAME,
            user_domain_name=OPENSTACK_USER_DOMAIN_NAME,
            project_domain_name=OPENSTACK_PROJECT_DOMAIN_NAME
        )

    @staticmethod
    def upload_file(conn, container_name, filename, file_data, content_type):
        try:
            conn.object_store.upload_object(
                container=container_name,
                name=filename,
                data=file_data,
                content_type=content_type,
            )
            print(f"File '{filename}' uploaded to '{container_name}' successfully.")
        except Exception as e:
            print(f"Failed to upload file: {str(e)}")
            raise

def create_container(container_name):
    try:
        conn = ContainerSecurityFunc.connect_openstack()
        existing_containers = [container.name for container in conn.object_store.containers()]
        if container_name in existing_containers:
            return True
        conn.object_store.create_container(container_name)
        return True
    except Exception as e:
        logger.error(f"Error creating container: {str(e)}")
        return False

def Home(request):
    return render(request, "home.html")

def about(request):
    return HttpResponse("This is about page")

@csrf_exempt
def get_container_name(request):
    try:
        user = request.user
        doctor = Doctor.objects.get(username=user.username)
        if doctor.container_name:
            return JsonResponse({"container_name": doctor.container_name})
        return JsonResponse({"error": "No container found"}, status=404)
    except Doctor.DoesNotExist:
        return JsonResponse({"error": "Doctor not found"}, status=404)
    except Exception as e:
        print("Error in get_container_name:", str(e))
        return JsonResponse({"error": "Server error"}, status=500)

@csrf_exempt
def upload_file(request):
    if request.method == "GET":
        return render(request, 'upload.html')
    elif request.method == "POST":
        try:
            conn = ContainerSecurityFunc.connect_openstack()
            uploaded_file = request.FILES.get("file")
            container_name = request.POST.get("container_name")
            if not uploaded_file:
                return JsonResponse({"error": "File is required"}, status=400)
            if not container_name:
                return JsonResponse({"error": "Container name is required"}, status=400)
            file_data = uploaded_file.read()
            file_name = uploaded_file.name
            ContainerSecurityFunc.upload_file(conn, container_name, file_name, file_data, uploaded_file.content_type)
            return JsonResponse({"message": "File uploaded successfully."})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Only POST method allowed"}, status=405)

@login_required
def view_files(request):
    user = request.user
    try:
        doctor = Doctor.objects.get(username=user.username)
        container_name = doctor.container_name
        conn = ContainerSecurityFunc.connect_openstack()
        file_list = [
            {"name": obj.name, "size": obj.content_length, "is_encrypted": obj.name.endswith(".enc")}
            for obj in conn.object_store.objects(container_name)
        ]
        return render(request, 'view_files.html', {"files": file_list})
    except Doctor.DoesNotExist:
        return JsonResponse({"error": "Doctor not found in the database"}, status=404)
    except Exception as e:
        return JsonResponse({"error": f"Error fetching files: {e}"}, status=500)

@csrf_exempt
def download_file(request, file_name):
    if request.method == "GET":
        try:
            doctor = get_object_or_404(Doctor, user=request.user)
            container_name = doctor.container_name
            conn = ContainerSecurityFunc.connect_openstack()
            file_object = conn.object_store.download_object(container=container_name, obj=file_name)
            if file_object is None:
                return JsonResponse({"error": "File not found"}, status=404)
            response = HttpResponse(file_object, content_type="application/octet-stream")
            response["Content-Disposition"] = f'attachment; filename="{file_name}"'
            return response
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def signup(request):
    try:
        if request.method == "GET":
            return render(request, 'signup.html')
        if request.method == "POST":
            try:
                data = json.loads(request.body.decode('utf-8'))
            except json.JSONDecodeError:
                return JsonResponse({"error": "Invalid JSON format"}, status=400)
            logger.info("Parsed Data: %s", data)
            required_fields = ["first-name", "last-name", "email", "mobile", "password", "date-of-birth",
                              "gender", "department", "designation", "address", "country", "container-name"]
            missing_fields = [field for field in required_fields if field not in data or not data[field]]
            if missing_fields:
                return JsonResponse({"error": f"Missing fields: {', '.join(missing_fields)}"}, status=400)
            first_name = data["first-name"]
            last_name = data["last-name"]
            email = data["email"]
            mobile = data["mobile"]
            password = data["password"]
            date_of_birth = data["date-of-birth"]
            gender = data["gender"]
            department = data["department"]
            designation = data["designation"]
            address = data["address"]
            country = data["country"]
            container_name = data["container-name"]
            if User.objects.filter(email=email).exists():
                return JsonResponse({"error": "Email already registered"}, status=400)
            try:
                dob = datetime.strptime(date_of_birth, '%d/%m/%Y').date()
                logger.info(f"Parsed DOB: {dob.strftime('%d/%m/%Y')}")
            except ValueError:
                return JsonResponse({"error": "Invalid date format. Use DD/MM/YYYY (e.g., 17/03/2025)"}, status=400)
            logger.info(f"Creating OpenStack container: {container_name}")
            if not create_container(container_name):
                return JsonResponse({"error": "Failed to create OpenStack container"}, status=500)
            user = User.objects.create_user(
                username=first_name,
                email=email.lower(),
                password=password,
                first_name=first_name,
                last_name=last_name
            )
            logger.info(f"Created user - Username: {user.username}, Email: {user.email}, Password Hash: {user.password}")
            doctor = Doctor.objects.create(
                user=user,
                username=first_name,
                mobile=mobile,
                date_of_birth=dob,
                gender=gender,
                department=department,
                designation=designation,
                address=address,
                country=country,
                container_name=container_name
            )
            doctor_keys = DoctorKey(user=user)
            doctor_keys.generate_keys()
            login(request, user)
            logger.info(f"User logged in after signup: {request.user.is_authenticated}")
            return JsonResponse({"message": "Signup successful", "container": container_name}, status=201)
    except Exception as e:
        logger.error(f"Signup error: {str(e)}", exc_info=True)
        return JsonResponse({"error": "Internal server error"}, status=500)
    return JsonResponse({"error": "Invalid request"}, status=400)

@login_required
def dashboard_view(request):
    user = request.user
    try:
        doctor = Doctor.objects.get(user=user)
        doctor_name = doctor.username
    except Doctor.DoesNotExist:
        doctor_name = user.username
    return render(request, 'dashboard.html', {'doctor_name': doctor_name})

@csrf_exempt
def login_view(request):
    print("Login function triggered")
    if request.method == "GET":
        return render(request, 'login.html')
    elif request.method == "POST":
        try:
            username = request.POST.get("username")
            password = request.POST.get("password")
            if not username or not password:
                try:
                    data = json.loads(request.body)
                    print("Received JSON data:", data)
                    username = data.get("username")
                    password = data.get("password")
                except json.JSONDecodeError:
                    return JsonResponse({"error": "Invalid JSON format"}, status=400)
            if not username or not password:
                return JsonResponse({"error": "Username and password are required"}, status=400)
            user = authenticate(username=username, password=password)
            print("Authenticated user:", user)
            if user is not None:
                login(request, user)
                return JsonResponse({"message": "Login successful", "redirect": "dashboard.html"}, status=200)
            else:
                return JsonResponse({"error": "Invalid credentials"}, status=400)
        except Exception as e:
            print("Error:", e)
            return JsonResponse({"error": "Internal server error"}, status=500)
    return JsonResponse({"error": "Invalid request"}, status=400)

@csrf_exempt
def request_file(request):
    if request.method == "GET":
        return render(request, "request_file.html")
    elif request.method == "POST":
        try:
            data = json.loads(request.body)
            filename = data.get("filename")
            sender_name = data.get("sender")
            requester_name = data.get("requester")
            sender = get_object_or_404(User, username=sender_name)
            requester = get_object_or_404(User, username=requester_name)
            if sender == requester:
                return JsonResponse({"error": "Sender and requester cannot be the same"}, status=400)
            doctor_key = DoctorKey.objects.filter(user=requester).first()
            if not doctor_key:
                return JsonResponse({"error": "Requester does not have a public key"}, status=400)
            new_request = Request.objects.create(
                filename=filename,
                sender=sender,
                requester=requester,
                status="Pending"
            )
            return JsonResponse({
                "message": "Request sent successfully",
                "request_id": new_request.id,
                "requester": requester.username,
                "receiver": sender.username,
                "filename": filename,
                "requester_public_key": doctor_key.public_key.decode()
            }, status=201)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def approve_request(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            request_id = data.get("requestId")
            file_request = Request.objects.filter(id=request_id, status="Pending").first()
            if not file_request:
                return JsonResponse({"error": "No pending request found"}, status=400)
            file_request.status = "Approved"
            file_request.save()
            return JsonResponse({"message": "Request approved successfully"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def send_file(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            sender_name = data.get("sender")
            receiver_name = data.get("receiver")
            filename = data.get("filename")
            if not sender_name or not receiver_name or not filename:
                return JsonResponse({"error": "Missing required fields"}, status=400)
            sender = Doctor.objects.get(username=sender_name)
            receiver = Doctor.objects.get(username=receiver_name)
            sender_container = sender.container_name
            receiver_container = receiver.container_name
            print(f"Sender container: {sender_container}, Receiver container: {receiver_container}")
            sender_key = DoctorKey.objects.get(user=sender.user)
            receiver_key = DoctorKey.objects.get(user=receiver.user)
            sender_private_key = load_dh_private_key(sender_key.private_key.strip())
            receiver_public_key = load_dh_public_key(receiver_key.public_key.strip())
            sender_private_number = sender_private_key.private_numbers().x
            receiver_public_number = receiver_public_key.public_numbers().y
            dh_p = sender_private_key.private_numbers().public_numbers.parameter_numbers.p
            shared_secret = pow(receiver_public_number, sender_private_number, dh_p)
            shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
            aes_key = SHA256.new(shared_secret_bytes).digest()
            conn = ContainerSecurityFunc.connect_openstack()
            file_data = conn.object_store.download_object(container=sender_container, obj=filename)
            print(f"📂 Fetched file '{filename}' size: {len(file_data)} bytes")
            print(f"Fetched content: {file_data}")
            iv = os.urandom(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
            final_encrypted_data = iv + encrypted_data
            print(f"Encrypted file size: {len(final_encrypted_data)} bytes")
            conn.object_store.create_object(
                container=receiver_container,
                name=filename + ".enc",
                data=final_encrypted_data
            )
            print(f"Uploaded '{filename + '.enc'}' to {receiver_container}, size: {len(final_encrypted_data)} bytes")
            new_file = File.objects.create(
                filename=filename + ".enc",
                encryption_key=shared_secret_bytes,
                sender_id=sender.user.id,
                receiver_id=receiver.user.id
            )
            new_file.save()
            return JsonResponse({"message": "File sent successfully!"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def decrypt_file(request, filename):
    if request.method == "POST":
        try:
            user = request.user
            file_entry = File.objects.filter(filename=filename, receiver_id=user.id).latest('id')
            shared_secret_bytes = file_entry.encryption_key
            print(f"Shared secret length: {len(shared_secret_bytes)} bytes")
            aes_key = sha256(shared_secret_bytes).digest()
            print(f"AES key length: {len(aes_key)} bytes")
            conn = ContainerSecurityFunc.connect_openstack()
            logged_in_doctor = Doctor.objects.get(user=request.user)
            doctor_container = logged_in_doctor.container_name
            print(f"Container: {doctor_container}, File: {filename}")
            encrypted_data = conn.object_store.download_object(container=doctor_container, obj=filename)
            print(f"Encrypted file size: {len(encrypted_data)} bytes")
            if len(encrypted_data) < 16:
                return JsonResponse({"error": "Invalid encrypted file format: File too small"}, status=400)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            print(f"IV length: {len(iv)}, Ciphertext length: {len(ciphertext)}")
            if len(ciphertext) % AES.block_size != 0:
                return JsonResponse({"error": "Invalid ciphertext length: Not a multiple of block size"}, status=400)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded_data = cipher.decrypt(ciphertext)
            print(f"Decrypted padded data size: {len(decrypted_padded_data)} bytes")
            decrypted_data = unpad(decrypted_padded_data, AES.block_size)
            print(f"Decrypted file size: {len(decrypted_data)} bytes")
            decrypted_filename = filename.replace(".enc", ".dec")
            conn.object_store.create_object(
                container=doctor_container,
                name=decrypted_filename,
                data=decrypted_data
            )
            return JsonResponse({"success": True, "decrypted_filename": decrypted_filename})
        except File.DoesNotExist:
            return JsonResponse({"error": "File not found"}, status=404)
        except ValueError as ve:
            return JsonResponse({"error": f"Decryption failed: Invalid padding or data - {str(ve)}"}, status=400)
        except Exception as e:
            return JsonResponse({"error": f"Decryption failed: {str(e)}"}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

from cryptography.hazmat.backends import default_backend
