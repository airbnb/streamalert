# Move into the source tree shared directory
cd /vagrant

# Enable the `workon` command
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
workon streamalert

# Install the requirements.txt into the streamalert virtualenv
pip install -r requirements.txt
