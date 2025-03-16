import openstack
import os
from openstack import connection


def get_openstack_connection():
    conn = openstack.connection.Connection(
        auth_url=os.getenv("OS_AUTH_URL"),
        project_name=os.getenv("OS_PROJECT_NAME"),
        username=os.getenv("OS_USERNAME"),
        password=os.getenv("OS_PASSWORD"),
        project_domain_id=os.getenv("OS_PROJECT_DOMAIN_ID", "default"),  # Use domain ID
        user_domain_id=os.getenv("OS_USER_DOMAIN_ID", "default")  # Use domain ID
    )
    return conn

def upload_file_to_openstack(container_name, file_name, file_data):
    """Uploads a file to an OpenStack container."""
    conn = get_openstack_connection()
    conn.object_store.create_object(
        container=container_name,
        name=file_name,
        data=file_data
    )
    return f"File {file_name} uploaded successfully!"

def list_files_in_container(container_name):
    conn = connection.Connection(
        auth_url="localhost/dashboard/auth/login/",  # Update this if your OpenStack uses a different URL
        project_name="",
        username="admin",
        password="user",  # Replace with actual password or use environment variables
        user_domain_name="Default",
        project_domain_name="Default"
    )
    
    files = conn.object_store.objects(container=container_name)
    return [file.name for file in files]

def download_file_from_openstack(container_name, file_name):
    """Downloads a file from an OpenStack container."""
    conn = get_openstack_connection()
    obj = conn.object_store.get_object(container_name, file_name)
    return obj.data