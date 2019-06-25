# Install the unzip utility
apt-get install unzip -y

# Pull down the version of Terraform that we want from the remote
wget https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip

# Unzip the Terraform binary, give it executable permissions, and put it in $PATH
unzip terraform_${TERRAFORM_VERSION}_linux_amd64.zip
chmod +x terraform
mv terraform /usr/bin/terraform
