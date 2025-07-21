
import requests
from requests.auth import HTTPBasicAuth

def list_dockerhub_tags(image_name:str, username:str=None, password:str=None)-> list:
    """
    List tags from Docker Hub using the Docker Hub API (token-based authentication if credentials are provided).

    :param image_name: Image name (e.g., "library/nginx" or "username/image")
    :param username: Optional Docker Hub username
    :param password: Optional Docker Hub password
    :return: List of tags or error message
    """
    tags = []
    url = f"https://hub.docker.com/v2/repositories/{image_name}/tags?page_size=100"

    headers = {}
    if username and password:
        # Get Docker Hub token
        auth_resp = requests.post(
            "https://hub.docker.com/v2/users/login/",
            json={"username": username, "password": password}
        )
        if auth_resp.status_code != 200:
            return f"Authentication failed: {auth_resp.text}"
        token = auth_resp.json().get("token")
        headers = {"Authorization": f"JWT {token}"}

    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            return f"Error: {resp.status_code} - {resp.text}"
        data = resp.json()
        tags.extend([tag["name"] for tag in data["results"]])
        url = data.get("next")

    return tags

def list_privateregistry_tags(image_name:str, registry:str, username:str=None, password:str=None, protocol:str='https', timeout:int=10):
    """
    List tags from a private Docker Registry (v2) using Basic Auth if provided.

    :param image_name: Image name (e.g., "myproject/myimage")
    :param registry: Registry domain (e.g., "harbor.example.com")
    :param username: Optional username
    :param password: Optional password or token
    :return: List of tags or error message
    """

    url = f"{registry}/v2/{image_name}/tags/list"
    # Ensure the URL starts with the correct protocol
    if not registry.startswith(('http://', 'https://')):
        url = f"{protocol}://{url}" 

    auth = HTTPBasicAuth(username, password) if username and password else None

    try:
        response = requests.get(url, auth=auth, timeout=timeout)
        if response.status_code == 200:
            return response.json().get("tags", [])
        else:
            return f"Error {response.status_code}: {response.text}"
    except requests.exceptions.Timeout as e:
        return f"Time out Exception occurred: {e}"
    except Exception as e:
        return f"Exception occurred: {e}"


def list_registry_tags(image_name:str, registry:str=None, username:str=None, password:str=None, protocol:str='https') -> list:
    tags = None
    if not registry or registry == "docker.io":
        # Docker Hub
        tags = list_dockerhub_tags(image_name, username, password)
    else:
        # Private registry
        tags = list_privateregistry_tags(image_name, registry, username, password, protocol)
    return tags
