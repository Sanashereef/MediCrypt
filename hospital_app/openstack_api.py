import openstack

def connect_openstack():
    """Authenticate and return OpenStack connection."""
    return openstack.connect(
        auth_url="http://127.0.0.1/identity/",
        username="admin",
        password="user",
        user_domain_name="Default",
        project_domain_name="Default",
    )

def create_container(container_name):
    """Create an OpenStack container when a doctor signs up."""
    conn = connect_openstack()

    # Check if the container exists
    existing_container = conn.object_store.get_container(container_name)

    if not existing_container:
        conn.object_store.create_container(container_name)
        print(f"✅ Container '{container_name}' created in OpenStack")
    else:
        print(f"⚠️ Container '{container_name}' already exists")
