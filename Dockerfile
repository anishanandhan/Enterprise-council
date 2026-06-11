# Use official Python 3.11 slim image
FROM python:3.11-slim

# Install essential system tools
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy python dependencies file and install them
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the rest of the project files
COPY . .

# Ensure startup script is executable
RUN chmod +x start.sh

# Expose ports (8080 for Streamlit, 8001 for FastAPI)
EXPOSE 8080
EXPOSE 8001

# Execute startup script
CMD ["./start.sh"]
