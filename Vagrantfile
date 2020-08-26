def patch_libssl(machine)
  # This fixes the interactive prompt when updating libssl
  machine.vm.provision :shell,
                       inline: "sudo apt-get update -y -qq && "\
                         "sudo dpkg-reconfigure libc6 && "\
                         "export DEBIAN_FRONTEND=noninteractive && "\
                         "sudo -E apt-get -q --option \"Dpkg::Options::=--force-confold\" --assume-yes install libssl1.1"
end

def configure_python(machine, version)
  # Install the virtualenv and virtualenvwrapper dependencies
  machine.vm.provision :shell,
                   path: "vagrant/cli/python-virtualenvwrapper/install.sh",
                   # We need root to update & install the packages
                   privileged: true,
                   env: {
                     PYTHON_VERSION: "python#{version.to_s}"
                   }

  # Configure the default vagrant user bash session with the virtualenv
  machine.vm.provision :shell,
                   path: "vagrant/cli/python-virtualenvwrapper/configure.sh",
                   # Install this to the vagrant user (unprivileged default)
                   privileged: false,
                   # Reset the terminal session so changes are sourced in
                   # subsequent shells
                   reset: true,
                   # Provide the shell script with the version of Python to
                   # install.
                   env: {
                     PYTHON_VERSION: "python#{version.to_s}"
                   }
end

STREAMALERT_SHELL_ENV = %{
export SA_EMAIL='#{ENV.fetch('SA_EMAIL', 'example@example.com')}'
}

def configure_streamalert(machine)
  # Install streamalert and it's dependencies
  # NOTE: The `aws` cli tool is installed as a dependency, thus it is
  # available once streamalert is installed.
  machine.vm.provision :shell,
                   path: "vagrant/cli/streamalert/install.sh",
                   # Install this to the vagrant user (unprivileged default)
                   privileged: true

  # Configure streamalert with required environment variables
  machine.vm.provision :shell,
                   # Append the environment variables to the .bashrc for
                   # the vagrant user (unprivileged default)
                   inline: "echo \"#{STREAMALERT_SHELL_ENV}\" >> ~/.bashrc",
                   # Install this to the vagrant user (unprivileged default)
                   privileged: false

  # Configure streamalert once the environment variables have been defined
  machine.vm.provision :shell,
                   path: "vagrant/cli/streamalert/configure.sh",
                   privileged: false
end

TERRAFORM_VERSION = ENV.fetch('SA_TERRAFORM_VERSION', '0.13.0')
def configure_terraform(machine)
  # Install terraform with the specified version.
  machine.vm.provision :shell,
                       path: "vagrant/cli/terraform/install.sh",
                       # Provide the shell script with the version of terraform
                       # to install.
                       env: {
                         TERRAFORM_VERSION: TERRAFORM_VERSION
                       }
end

FINAL_MESSAGE = %{
Your local environment has been created! To provision the remote infrastructure,
execute "yes | $PROJECT_ROOT/manage.py init". To verify the infrastructure was
created correctly, run "aws s3 ls | grep streamalert".

The following lines were appended to the vagrant (default) user's
~/.bashrc:

#{STREAMALERT_SHELL_ENV}

}

def final_message(machine)
  # Output the final message for easy copy/paste of next steps. We scope it
  # in the vm via inline shell provisioner so it makes it easy to grep for
  # the last N machine output lines.
  machine.vm.provision :shell,
                   inline: "cat << EOF #{FINAL_MESSAGE}\nEOF",
                   # We don't need root to echo
                   privileged: false
end

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/bionic64"

  config.vm.define :development_py2, autostart: false do |py2|
    patch_libssl(py2)
    configure_python(py2, 2.7)
    configure_terraform(py2)
    configure_streamalert(py2)
    final_message(py2)
  end

  config.vm.define :development_py3, primary: true do |py3|
    patch_libssl(py3)
    configure_python(py3, 3.7)
    configure_terraform(py3)
    configure_streamalert(py3)
    final_message(py3)
  end

  config.ssh.forward_env = [
    'AWS_DEFAULT_REGION',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN'
  ]
end
