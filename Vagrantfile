Vagrant.configure("2") do |config|
    config.vm.box = "cloud-image/ubuntu-24.04"
    config.vm.box_version = "20240423.0.0"
    config.vm.provider "libvirt" do |v|
        v.memory = 1024
        v.cpus = 4
      end
    config.vm.network "private_network", ip: "192.168.121.135"
    config.vm.hostname = "testsrv.local"
    config.vm.provision "shell" do |s|
        ssh_pub_key = File.readlines("/home/user/.ssh/id_rsa.pub").first.strip
        s.inline = <<-SHELL
          echo #{ssh_pub_key} >> /home/vagrant/.ssh/authorized_keys
          echo #{ssh_pub_key} >> /root/.ssh/authorized_keys
        SHELL
      end
  end