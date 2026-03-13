FROM node:18-bullseye-slim

# Install Python and pip
RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/app

# Copy root package.json if it exists
COPY package*.json ./

# Copy backend package.json and install Node dependencies
COPY backend/package*.json ./backend/
RUN cd backend && npm install --production

# Copy requirements.txt and install Python dependencies
COPY requirements.txt ./
RUN pip3 install -r requirements.txt --break-system-packages

# Copy the rest of the application
COPY . .

# Expose the API port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
