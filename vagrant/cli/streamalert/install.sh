# Install git so we can clone the streamalert repository
apt-get install git awscli -y

# Configure ssh to allow env variables AWS_* to be passed through
cp /vagrant/vagrant/cli/streamalert/sshd_config /etc/ssh/sshd_config && \
  /etc/init.d/ssh restart

