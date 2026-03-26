#!/bin/bash
# Start both honeypot and operator dashboard on GCP
# Make sure this runs on app startup

echo "Starting Honeypot Security Platform..."

# Create data directory if it doesn't exist
mkdir -p data

# Install dependencies
pip install -r requirements.txt

# Start honeypot on port 5000
echo "Starting honeypot on port 5000..."
gunicorn run:app --bind 0.0.0.0:5000 --workers 4 &
HONEYPOT_PID=$!

# Wait for honeypot to start
sleep 3

# Start operator dashboard on port 5001
echo "Starting operator dashboard on port 5001..."
python operator_dashboard.py &
OPERATOR_PID=$!

echo "Both services started!"
echo "Honeypot: http://your-gcp-domain:5000"
echo "Operator: http://your-gcp-domain:5001"

# Keep both running
wait $HONEYPOT_PID $OPERATOR_PID
