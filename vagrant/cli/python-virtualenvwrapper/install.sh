# Install python dependencies
apt-get install python-pip python3.9-venv virtualenvwrapper -y

# Install Python with the version specified from the deadsnakes ppa
apt-get install software-properties-common -y
add-apt-repository ppa:deadsnakes/ppa -y
apt-get update
apt-get install ${PYTHON_VERSION} -y

# Install the dev headers for extensions support
apt-get install ${PYTHON_VERSION}-dev -y
