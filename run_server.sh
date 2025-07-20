#!/bin/bash

# Get the local IP address
LOCAL_IP=$(hostname -I | awk '{print $1}')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="127.0.0.1"
fi

echo "Starting Flask server on $LOCAL_IP:12000"
echo "This server will be accessible both locally and over the internet"
echo "Web interface: http://$LOCAL_IP:12000"
echo "RAT devices connect to: http://$LOCAL_IP:12000/api/rat_connect"

# Install required Python packages
pip install -r requirements.txt

# Start the Flask server
cd /workspace/RAT
python app.py