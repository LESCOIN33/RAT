# RAT with Dual IP Configuration

This RAT (Remote Access Tool) has been modified to work with both local and public IP addresses, allowing it to function in both local network and over the internet.

## Features

1. **Dual IP Configuration**: The RAT will first try to connect using the local IP address (same WiFi network). If that fails, it will automatically switch to the public IP address.

2. **Automatic IP Detection**: The server automatically detects and uses the local IP address of the machine it's running on.

3. **Persistent Connection**: The RAT will maintain a persistent connection to the server, even if the device is rebooted.

## How to Use

### 1. Compile the Java Code

```bash
./compile.sh
```

This will compile the Java code, create a JAR file, convert it to DEX, and generate the Smali files.

### 2. Run the Flask Server

```bash
./run_server.sh
```

This will start the Flask server on port 12000, which will be accessible both locally and over the internet.

### 3. Bind the APK

Use the web interface to bind the APK. The server will automatically inject both the local and public IP addresses into the APK.

### 4. Install the APK on the Target Device

Install the bound APK on the target device. The RAT will automatically connect to the server using either the local or public IP address, depending on which one is reachable.

## Configuration

The configuration is stored in the `assets/config.ini` file in the APK, which contains:

```ini
LOCAL_IP=192.168.1.100  # Your local IP address
PUBLIC_IP=your.public.ip  # Your public IP address
FLASK_PORT=12000  # Port for Flask API calls
RAT_PORT=12000  # Port for RAT connections
```

## Troubleshooting

If the RAT is not connecting:

1. Make sure the server is running
2. Check that the IP addresses in the config.ini file are correct
3. Ensure that the ports are open and accessible
4. Check the device logs for any errors