n_servers = 1
n_clients = 1

server_net = "172.16.1.10"
client_net = "172.16.1.11"
broker_mqtt_net = "172.16.1.100"

src_folder="src/"
dst_folder="~"

def add_ssh_key(config)
    ssh_pub_key = File.readlines("#{Dir.home}/.ssh/id_rsa.pub").first.strip
    config.vm.provision "shell" do |s|
      s.inline = <<-SHELL
        echo #{ssh_pub_key} >> /home/vagrant/.ssh/authorized_keys
        mkdir -p /root/.ssh/
        chmod 700 /root/.ssh/
        echo #{ssh_pub_key} >> /root/.ssh/authorized_keys
      SHELL
    end
end

Vagrant.configure("2") do |config|
    config.vm.synced_folder ".", "/home/vagrant/tfg"
    
    (1..n_servers).each do |i|
        config.vm.define "server-#{i}" do |node|
            node.vm.network :private_network, ip: "#{server_net}#{i}"
            node.vm.box = "ubuntu/focal64"
            node.vm.provider "virtualbox" do |pmv|
                pmv.memory = 512
                pmv.cpus   = 1
            end
            node.vm.hostname = "server-#{i}"
            add_ssh_key(config)
        end
    end

    (1..n_clients).each do |i|
        config.vm.define "client-#{i}" do |node|
            node.vm.network :private_network, ip: "#{client_net}#{i}"
            node.vm.box = "ubuntu/focal64"
            node.vm.provider "virtualbox" do |pmv|
                pmv.memory = 512
                pmv.cpus   = 1
            end
            node.vm.hostname = "client-#{i}"
            add_ssh_key(config)
        end
        
    end

    config.vm.define "broker-mqtt" do |node|
        node.vm.network :private_network, ip: "#{broker_mqtt_net}"
        node.vm.box = "ubuntu/focal64"
        node.vm.provider "virtualbox" do |pmv|
            pmv.memory = 512
            pmv.cpus   = 1
        end
        node.vm.hostname = "broker-mqtt"
        add_ssh_key(config)
    end

    #config.vm.synced_folder $src_folder, $dst_folder
end
