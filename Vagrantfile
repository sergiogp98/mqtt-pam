n_servers = 1
n_clients = 1

server_net = "172.16.1.10"
client_net = "172.16.1.11"
broker_mqtt_net = "172.16.1.100"

Vagrant.configure("2") do |config|
    (1..n_servers).each do |i|
        config.vm.define "server-#{i}" do |node|
            node.vm.network :private_network, ip: "#{server_net}#{i}"
            node.vm.box = "ubuntu/bionic64"
            node.vm.provider "virtualbox" do |pmv|
                pmv.memory = 512
                pmv.cpus   = 1
            end
            node.vm.hostname = "server-#{i}"
        end
    end

    (1..n_clients).each do |i|
        config.vm.define "client-#{i}" do |node|
            node.vm.network :private_network, ip: "#{client_net}#{i}"
            node.vm.box = "ubuntu/bionic64"
            node.vm.provider "virtualbox" do |pmv|
                pmv.memory = 512
                pmv.cpus   = 1
            end
            node.vm.hostname = "client-#{i}"
        end
    end

    config.vm.define "broker-mqtt" do |node|
        node.vm.network :private_network, ip: "#{broker_mqtt_net}"
        node.vm.box = "centos/8"
        node.vm.provider "virtualbox" do |pmv|
            pmv.memory = 512
            pmv.cpus   = 1
        end
        node.vm.hostname = "broker-mqtt"
    end
end
