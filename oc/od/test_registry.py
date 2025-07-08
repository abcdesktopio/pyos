import registry


if __name__ == "__main__":
    myregistry = input("Enter registry (leave empty for Docker Hub): ").strip()
    image = input("Enter image name (e.g., 'library/nginx' or 'username/image'): ").strip()
    use_auth = input("Do you want to use authentication? (y/n): ").lower() == "y"

    username = password = None
    if use_auth:
        username = input("Username: ").strip()
        password = getpass("Password: ")

    tags = registry.list_registry_tags(image, myregistry, username, password)
    if isinstance(tags, list):
        print(f"\nTags for image '{image}':")
        for tag in tags:
            print(f" - {tag}")
    else:
        print(f"\n{tags}")
