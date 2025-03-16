from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User, AbstractUser
from django.contrib.auth.hashers import make_password

import openstack
import json
import os
import base64
import secrets
import tempfile

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


from .encryption import generate_dh_keys, derive_aes_key, encrypt_file

from django.views.decorators.csrf import csrf_exempt
from .encryption import generate_dh_keys, derive_aes_key, encrypt_file



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from .models import DoctorKey, Request, File


from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import login
from .models import Doctor, DoctorKey
import json
from datetime import datetime


from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
import json
from .models import File, Request, DoctorKey, User


from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from .models import DoctorKey, File, Request
from django.contrib.auth.models import User
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


from http.server import SimpleHTTPRequestHandler, HTTPServer
import logging
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


import os
import base64
import hashlib
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
import openstack
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh


def landing_page(request):
    return render(request, 'landing.html')

def received_requests(request):
    return render(request, 'received_requests.html')

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Doctor  # Import your Doctor model

@login_required
def view_profile(request):
    doctor = Doctor.objects.get(user_id=request.user.id)  # Fetch doctor details
    return render(request, 'profile.html', {'doctor': doctor})


from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Request


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Request  # Import the Request model


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from hospital_app.models import Request, Doctor  # Import models


from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)
    return redirect('login')  # Replace 'login' with your actual login page URL name
@login_required
def requested_files(request):
    doctor_id = request.user.id  # Assuming doctors are stored in the User model

    # Fetch pending and approved requests ordered by latest first
    requests = Request.objects.filter(sender_id=doctor_id).select_related('requester').order_by('-id')

    request_data = []
    for req in requests:
        requester_doctor = Doctor.objects.filter(id=req.requester_id).first()
        requester_name = requester_doctor.username if requester_doctor else "Unknown"

        request_data.append({
            "id": req.id,
            "requester_name": requester_name,
            "filename": req.filename,
            "status": req.status
        })

    return render(request, 'requested_files.html', {'requests': request_data})





class ContainerSecurityFunc:
    def connectOpenStack(auth_url, project_name, username, password):
        conn = openstack.connection.Connection(
            auth_url=str(auth_url),
            project_name = str(project_name),
            username = str(username),
            password = str(password),
            region_name="RegionOne",
            user_domain_name="Default",
            project_domain_name="Default"
        )
        return conn
    

    def upload_file(conn, container_name, filename, file_data, content_type):
        try:
            conn.object_store.upload_object(
                container=container_name,
                name=filename,  # File name without folder structure
                data=file_data,  # Uploads file content directly
                content_type=content_type,  # Ensure correct content type
            )
            print(f"File '{filename}' uploaded to '{container_name}' successfully.")
        except Exception as e:
            print(f"Failed to upload file: {str(e)}")
            raise

    




def create_container(container_name):
    try:
        # Connect to OpenStack
        conn = ContainerSecurityFunc.connectOpenStack(
            auth_url="http://127.0.0.1/identity",
            project_name="admin",
            username="admin",
            password="user"
        )

        # Check if container already exists
        existing_containers = [container.name for container in conn.object_store.containers()]
        if container_name in existing_containers:
            return True  # Container already exists

        # Create a new container
        conn.object_store.create_container(container_name)
        return True  # Container created successfully

    except Exception as e:
        logger.error(f"Error creating container: {str(e)}")
        return False  # Container creation failed

def Home(request):
    return render(request, "home.html")

def about(request):
    return HttpResponse("THis is about page")


from .models import Doctor  # Assuming 'Doctor' is the model representing hospital_app_doctor

@csrf_exempt
def get_container_name(request):
    try:
        user = request.user  # Get the logged-in user
        
        # Ensure user is linked to the Doctor model
        doctor = Doctor.objects.get(username=user.username)  # Fetch the doctor object
        
        if doctor.container_name:  # Check if container_name exists
            return JsonResponse({"container_name": doctor.container_name})
        else:
            return JsonResponse({"error": "No container found"}, status=404)

    except Doctor.DoesNotExist:
        return JsonResponse({"error": "Doctor not found"}, status=404)
    
    except Exception as e:
        print("Error in get_container_name:", str(e))  # Debugging output
        return JsonResponse({"error": "Server error"}, status=500)

@csrf_exempt
def upload_file(request):
    if request.method == "GET":
            return render(request, 'upload.html')
    elif request.method == "POST":
        try:
            # Connect to OpenStack
            conn = ContainerSecurityFunc.connectOpenStack(auth_url="http://127.0.0.1/identity", project_name="admin", username="admin", password="user")

            # Get file and container name from request
            uploaded_file = request.FILES.get("file")  # Django File Object
            container_name = request.POST.get("container_name")  # Container name

            if not uploaded_file:
                return JsonResponse({"error": "File is required"}, status=400)

            if not container_name:
                return JsonResponse({"error": "Container name is required"}, status=400)

            # Read file content
            file_data = uploaded_file.read()
            file_name = uploaded_file.name  # Extract file name

            # Upload file to OpenStack
            ContainerSecurityFunc.upload_file(conn, container_name, file_name, file_data, uploaded_file.content_type)

            return JsonResponse({"message": "File uploaded successfully."})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Only POST method allowed"}, status=405)


    


@login_required
def view_files(request):
    user = request.user  # Get the logged-in doctor

    try:
        # Fetch the container name from the database
        doctor = Doctor.objects.get(username=user.username)
        container_name = doctor.container_name  # Assuming 'container_name' is a column in the table

        # Connect to OpenStack and get files
        conn = conn = ContainerSecurityFunc.connectOpenStack(
                auth_url="http://127.0.0.1/identity",
                project_name="admin",
                username="admin",
                password="user"
            )

        objects = conn.object_store.objects(container_name)

         # Get file list from OpenStack container
        file_list = []
        for obj in conn.object_store.objects(container_name):
            file_list.append({
                "name": obj.name, 
                "size": obj.content_length, 
                "is_encrypted": obj.name.endswith(".enc")  # Flag encrypted files
            })

    except Doctor.DoesNotExist:
        return JsonResponse({"error": "Doctor not found in the database"}, status=404)
    except Exception as e:
        return JsonResponse({"error": f"Error fetching files: {e}"}, status=500)

    return render(request, 'view_files.html', {"files": file_list})



from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.shortcuts import get_object_or_404
import openstack

from django.shortcuts import get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import openstack
import io

from django.shortcuts import get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
import openstack
import io
from django.http import FileResponse
from hospital_app.models import Doctor  # Adjust import as needed



@csrf_exempt
def download_file(request, file_name):
    if request.method == "GET":
        try:
            # Get the doctor linked to the logged-in user
            doctor = get_object_or_404(Doctor, user=request.user)
            container_name = doctor.container_name  

            # Connect to OpenStack
            conn = openstack.connection.Connection(
                auth_url="http://127.0.0.1/identity",
                project_name="admin",
                username="admin",
                password="user",
                user_domain_id="default",
                project_domain_id="default",
            )

            # 📌 Retrieve the file data
            file_object = conn.object_store.download_object(container=container_name, obj=file_name)

            if file_object is None:
                return JsonResponse({"error": "File not found"}, status=404)

            # 📌 Create response with the actual file content
            response = HttpResponse(file_object, content_type="application/octet-stream")
            response["Content-Disposition"] = f'attachment; filename="{file_name}"'
            return response

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
import logging
logger = logging.getLogger(__name__)



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

            # Adjusted required fields (removed container-name since frontend doesn’t send it)
            required_fields = ["first-name", "last-name", "email", "mobile", "password", "date-of-birth",
                               "gender", "department", "designation", "address", "country"]
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

            # Generate container_name (e.g., based on username or email)
            container_name = f"{first_name.lower()}_{mobile}"  # Example: john_1234567890

            if User.objects.filter(email=email).exists():
                return JsonResponse({"error": "Email already registered"}, status=400)

            try:
                dob = datetime.strptime(date_of_birth, '%d/%m/%Y').date()
            except ValueError:
                return JsonResponse({"error": "Invalid date format. Use DD/MM/YYYY"}, status=400)

            logger.info(f"Creating OpenStack container: {container_name}")
            if not create_container(container_name):
                return JsonResponse({"error": "Failed to create OpenStack container"}, status=500)

            user = User.objects.create_user(
                username=email,  # Use email as username for uniqueness
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )

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

            return JsonResponse({"message": "Signup successful", "container": container_name}, status=201)

    except Exception as e:
        logger.error(f"Signup error: {str(e)}", exc_info=True)
        return JsonResponse({"error": "Internal server error"}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)
def dashboard_view(request):
    return render(request, 'dashboard.html')  # Ensure this file exists


@csrf_exempt
def login_view(request):
    print("Login function triggered")  # Debugging

    if request.method == "GET":  
        return render(request, 'login.html')  # Render login page

    elif request.method == "POST":
        try:
            # Check if form data is sent (application/x-www-form-urlencoded)
            username = request.POST.get("username")
            password = request.POST.get("password")

            # If form data is not found, try JSON data
            if not username or not password:
                try:
                    data = json.loads(request.body)
                    print("Received JSON data:", data)  # Debugging
                    username = data.get("username")
                    password = data.get("password")
                except json.JSONDecodeError:
                    return JsonResponse({"error": "Invalid JSON format"}, status=400)

            if not username or not password:
                return JsonResponse({"error": "Username and password are required"}, status=400)

            # Authenticate user
            user = authenticate(username=username, password=password)
            print("Authenticated user:", user)  # Debugging

            if user is not None:
                login(request, user)
                return JsonResponse({"message": "Login successful","redirect": "dashboard.html"}, status=200)
            else:
                return JsonResponse({"error": "Invalid credentials"}, status=400)

        except Exception as e:
            print("Error:", e)
            return JsonResponse({"error": "Internal server error"}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)

@csrf_exempt
def request_file(request):
    if request.method == "GET":
        return render(request, "request_file.html")  # ✅ Load the frontend page

    elif request.method == "POST":
        try:
            data = json.loads(request.body)
            filename = data.get("filename")  # Requested file name
            sender_name = data.get("sender")  # Doctor who owns the file
            requester_name = data.get("requester")  # Doctor making the request

            # ✅ Get sender (doctor who owns the file)
            sender = get_object_or_404(User, username=sender_name)

            # ✅ Get requester (doctor making the request)
            requester = get_object_or_404(User, username=requester_name)

            # ✅ Check if requester's public key exists
            doctor_key = DoctorKey.objects.filter(user=requester).first()
            if not doctor_key:
                return JsonResponse({"error": "Requester does not have a public key"}, status=400)

            # ✅ Create request entry without checking file existence
            new_request = Request.objects.create(
                filename=filename,  # Store filename as string
                sender=sender,  # Store sender (User object)
                requester=requester,  # Store requester (User object)
                status="Pending"
            )

            return JsonResponse({
                "message": "Request sent successfully",
                "request_id": new_request.id,
                "requester": requester.username,
                "receiver": sender.username,
                "filename": filename,
                "requester_public_key": doctor_key.public_key.decode()  # Send public key as string
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
            request_id = data.get("requestId")  # Use requestId from the request body

            # Find the request by ID
            file_request = Request.objects.filter(id=request_id, status="Pending").first()
            if not file_request:
                return JsonResponse({"error": "No pending request found"}, status=400)

            # Approve the request
            file_request.status = "Approved"
            file_request.save()

            return JsonResponse({"message": "Request approved successfully"})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=400)


from openstack import connection

import logging
from openstack import connection
from .models import User, Request, Doctor  # Ensure models are correctly imported


from .models import User, File  # Assuming your models have key storage

import json
import io
import base64
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from hospital_app.models import Doctor, DoctorKey
from openstack import connection

# OpenStack Connection
conn = openstack.connection.Connection(
            auth_url="http://127.0.0.1/identity",
            project_name="admin",
            username="admin",
            password="user",
            user_domain_id="default",
            project_domain_id="default",
        )
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
import io
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from .models import Doctor, DoctorKey  # Import your models
from django.shortcuts import get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
import openstack
from django.http import FileResponse
from hospital_app.models import Doctor  # Adjust import as needed

# Function to load Diffie-Hellman private key from PEM
def load_dh_private_key(pem_data):
    return serialization.load_pem_private_key(
        pem_data,  
        password=None, 
        backend=default_backend()
    )

# Function to load Diffie-Hellman public key from PEM
def load_dh_public_key(pem_data):
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )

# @csrf_exempt
# def send_file(request):
#     if request.method == "POST":
#         try:
#             # Parse request data
#             data = json.loads(request.body)
#             sender_name = data.get("sender")
#             receiver_name = data.get("receiver")
#             filename = data.get("filename")

#             if not sender_name or not receiver_name or not filename:
#                 return JsonResponse({"error": "Missing required fields"}, status=400)

#             # Fetch sender and receiver details
#             sender = Doctor.objects.get(username=sender_name)
#             receiver = Doctor.objects.get(username=receiver_name)

#             sender_container = sender.container_name
#             receiver_container = receiver.container_name

#             # 📌 3. Fetch sender's private key and receiver's public key
#             sender_key = DoctorKey.objects.get(user=sender.user)
#             receiver_key = DoctorKey.objects.get(user=receiver.user)

#             # 📌 4. Load keys properly
#             sender_private_key = load_dh_private_key(sender_key.private_key.strip())
#             receiver_public_key = load_dh_public_key(receiver_key.public_key.strip())

#             # 📌 5. Extract raw integer values needed for Diffie-Hellman
#             sender_private_number = sender_private_key.private_numbers().x
#             receiver_public_number = receiver_public_key.public_numbers().y
#             dh_p = sender_private_key.private_numbers().public_numbers.parameter_numbers.p


#             # 📌 6. Perform Diffie-Hellman key exchange
#             shared_secret = pow(receiver_public_number, sender_private_number, dh_p)
#             shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')

#             # 📌 7. Generate AES key from shared secret using SHA-256
#             aes_key = SHA256.new(shared_secret_bytes).digest()

#             # 📌 8. **Fixing OpenStack File Download**
#             # Open a memory stream to download the object
#             file_stream = io.BytesIO()
#             conn.object_store.download_object(
#                 container=sender_container,
#                 obj=filename,  # Ensure 'obj' is correct
#                 stream=file_stream
#             )
#             file_data = file_stream.getvalue()
#             print(f"📂 Fetched file '{filename}' size: {len(file_data)} bytes")




#             # 📌 9. Encrypt the file using AES
#             iv = os.urandom(16)  # Generate IV explicitly (16 bytes)

#             cipher = AES.new(aes_key, AES.MODE_CBC, iv)
#             encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

#             # Combine IV and encrypted data correctly
#             final_encrypted_data = iv + encrypted_data  # Ensure IV is the first 16 bytes
#             print("Original file size:", len(file_data))
#             print("Encrypted file size:", len(final_encrypted_data))


#             # 📌 10. Upload the encrypted file to the receiver's OpenStack container
#             conn.object_store.create_object(
#                 container=receiver_container,
#                 name=filename + ".enc",
#                 data=final_encrypted_data
#             )
#             # 📌 **INSERT RECORD INTO FILES TABLE**
#             new_file = File.objects.create(
#                 filename=filename + ".enc",
#                 encryption_key=shared_secret_bytes,  # Store encrypted key
#                 sender_id=sender.user.id,
#                 receiver_id=receiver.user.id
#             )
#             new_file.save()

#             return JsonResponse({"message": "File sent successfully!"})

#         except Doctor.DoesNotExist:
#             return JsonResponse({"error": "Sender or Receiver not found"}, status=404)
#         except DoctorKey.DoesNotExist:
#             return JsonResponse({"error": "Key not found for sender or receiver"}, status=404)
#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=500)
        

# @csrf_exempt #latest code
# def send_file(request):
#     if request.method == "POST":
#         try:
#             # Parse request data
#             data = json.loads(request.body)
#             sender_name = data.get("sender")
#             receiver_name = data.get("receiver")
#             filename = data.get("filename")

#             if not sender_name or not receiver_name or not filename:
#                 return JsonResponse({"error": "Missing required fields"}, status=400)

#             # Fetch sender and receiver details
#             sender = Doctor.objects.get(username=sender_name)
#             receiver = Doctor.objects.get(username=receiver_name)

#             sender_container = sender.container_name
#             receiver_container = receiver.container_name

#             # 📌 3. Fetch sender's private key and receiver's public key
#             sender_key = DoctorKey.objects.get(user=sender.user)
#             receiver_key = DoctorKey.objects.get(user=receiver.user)

#             # 📌 4. Load keys properly
#             sender_private_key = load_dh_private_key(sender_key.private_key.strip())
#             receiver_public_key = load_dh_public_key(receiver_key.public_key.strip())

#             # 📌 5. Extract raw integer values needed for Diffie-Hellman
#             sender_private_number = sender_private_key.private_numbers().x
#             receiver_public_number = receiver_public_key.public_numbers().y
#             dh_p = sender_private_key.private_numbers().public_numbers.parameter_numbers.p


#             # 📌 6. Perform Diffie-Hellman key exchange
#             shared_secret = pow(receiver_public_number, sender_private_number, dh_p)
#             shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')

#             # 📌 7. Generate AES key from shared secret using SHA-256
#             aes_key = SHA256.new(shared_secret_bytes).digest()

#             # 📌 8. **Fixing OpenStack File Download**
#             # Open a memory stream to download the object
#             file_data = conn.object_store.download_object(
#                 container=sender_container,
#                 obj=filename
#             )
#             print(f"📂 Fetched file '{filename}' size: {len(file_data)} bytes")
#             print(f"Fetched content: {file_data}")




#             # 📌 9. Encrypt the file using AES
#             iv = os.urandom(16)  # Generate IV explicitly (16 bytes)

#             cipher = AES.new(aes_key, AES.MODE_CBC, iv)
#             encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

#             # Combine IV and encrypted data correctly
#             final_encrypted_data = iv + encrypted_data  # Ensure IV is the first 16 bytes
#             print("Original file size:", len(file_data))
#             print("Encrypted file size:", len(final_encrypted_data))


#             # 📌 10. Upload the encrypted file to the receiver's OpenStack container
#             conn.object_store.create_object(
#                 container=receiver_container,
#                 name=filename + ".enc",
#                 data=final_encrypted_data
#             )
#             # 📌 **INSERT RECORD INTO FILES TABLE**
#             new_file = File.objects.create(
#                 filename=filename + ".enc",
#                 encryption_key=shared_secret_bytes,  # Store encrypted key
#                 sender_id=sender.user.id,
#                 receiver_id=receiver.user.id
#             )
#             new_file.save()

#             return JsonResponse({"message": "File sent successfully!"})

#         except Doctor.DoesNotExist:
#             return JsonResponse({"error": "Sender or Receiver not found"}, status=404)
#         except DoctorKey.DoesNotExist:
#             return JsonResponse({"error": "Key not found for sender or receiver"}, status=404)
#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=500)
        
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

            file_data = conn.object_store.download_object(
                container=sender_container,
                obj=filename
            )
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


import base64
import os
import io
import openstack
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import File, Doctor
from hashlib import sha256

@csrf_exempt
def decrypt_file(request, filename):
    if request.method == "POST":
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)

        try:
            user = request.user

            # Retrieve file and encryption key
            file_entry = File.objects.filter(filename=filename, receiver_id=user.id).latest('id')
            shared_secret_bytes = file_entry.encryption_key
            print(f"Shared secret length: {len(shared_secret_bytes)} bytes")

            # Derive AES key (matches encryption)
            aes_key = sha256(shared_secret_bytes).digest()
            print(f"AES key length: {len(aes_key)} bytes")  # Should be 32

            # Connect to OpenStack
            conn = openstack.connection.Connection(
                auth_url="http://127.0.0.1/identity",
                project_name="admin",
                username="admin",
                password="user",
                user_domain_id="default",
                project_domain_id="default",
            )

            # Fetch container
            logged_in_doctor = Doctor.objects.get(user=request.user)
            doctor_container = logged_in_doctor.container_name
            print(f"Container: {doctor_container}, File: {filename}")

            # Download encrypted file
            encrypted_data = conn.object_store.download_object(
                container=doctor_container,
                obj=filename
            )
            print(f"Encrypted file size: {len(encrypted_data)} bytes")

            # Check minimum size
            if len(encrypted_data) < 16:
                return JsonResponse({"error": "Invalid encrypted file format: File too small"}, status=400)

            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            print(f"IV length: {len(iv)}, Ciphertext length: {len(ciphertext)}")

            # Ensure ciphertext is a multiple of block size
            if len(ciphertext) % AES.block_size != 0:
                return JsonResponse({"error": "Invalid ciphertext length: Not a multiple of block size"}, status=400)

            # Decrypt
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded_data = cipher.decrypt(ciphertext)
            print(f"Decrypted padded data size: {len(decrypted_padded_data)} bytes")

            # Unpad
            decrypted_data = unpad(decrypted_padded_data, AES.block_size)
            print(f"Decrypted file size: {len(decrypted_data)} bytes")

            # Save decrypted file
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