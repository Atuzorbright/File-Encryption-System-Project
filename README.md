# Create an isolated virtual environment using Python 3.10+
conda create -n secure_share_env python=3.10 -y

# Activate the workspace environment
conda activate secure_share_env

# Install Flask, secure cryptography tools, and Werkzeug helpers
pip install Flask cryptography werkzeug

conda activate file_share
cd C:\Users\HP\Desktop\ufuoma
python app.py
