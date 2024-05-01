import paramiko

def main():
    # IP address of the server
    server_ip = '43.228.125.238'

    # Path to the private key file (.pem or .ppk)
    private_key_path = 'app/STSL_privatekey02.key'

    # Username for SSH authentication
    username = 'stablesail'

    # Create an SSH client object
    ssh_client = paramiko.SSHClient()

    # Load host keys (optional)
    ssh_client.load_system_host_keys()

    # Set policy to auto-add unknown hosts (optional)
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Load the private key
    private_key = paramiko.RSAKey.from_private_key_file(private_key_path)

    return ssh_client, server_ip, username, private_key

if __name__ == '__main__':
    main()