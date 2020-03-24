# Set up the virtual environment
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
mkvirtualenv --python=/usr/bin/$PYTHON_VERSION streamalert

# Add virtualenvwrapper to the bashrc
echo "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh" >> ~/.bashrc
echo "workon streamalert" >> ~/.bashrc
