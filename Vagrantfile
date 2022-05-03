# -*- mode: ruby -*-
# vi: set ft=ruby :

# Address of the attacker's server (exfiltration point).
ATTACKER_IP = "192.168.53.53"

# IP address of the target/victim.
TARGET_IP = "192.168.56.10"

# IP address of the DNS server/Detection node.
DNS_SERVER_IP = "192.168.56.15"

# The domain to use for exfiltration (1 label without TLD).
ATTACKER_DOMAIN = "exfil"

# The Top-Level-Domain to use for exfiltration.
ATTACKER_TLD = "xy"

# The TLD of StealthyVec's domains (has to be the same as in wordlists/domains.txt).
STEALTHYVEC_TLD = "xyz"

# The record type to use in queries.
RECORD_TYPE = "A"

# The address the Attacker server should respond with to every query.
RESPONSE_ADDRESS = "125.156.113.96"

Vagrant.configure("2") do |config|

    config.vm.define "target" do |target|
        target.vm.box = "generic/fedora34"
        target.vm.hostname = "target"
        target.vm.network "private_network", ip: TARGET_IP, name: "vboxnet1"
        target.vm.synced_folder ".", "/vagrant", disabled: true
    end

    config.vm.define "attacker" do |attacker|
        attacker.vm.box = "hashicorp/bionic64"
        attacker.vm.hostname = "attacker"
        attacker.vm.network "private_network", ip: ATTACKER_IP, name: "vboxnet0"
        attacker.vm.synced_folder ".", "/vagrant", disabled: true
    end

    config.vm.define "dnsserver" do |dnsserver|
        dnsserver.vm.box = "generic/ubuntu2004"
        dnsserver.vm.hostname = "dnsserver"
        dnsserver.vm.network "private_network", ip: DNS_SERVER_IP, name: "vboxnet1"
        dnsserver.vm.provider :virtualbox do |vb|
            vb.customize ["modifyvm", :id, "--memory", "4096"]
            vb.customize ["modifyvm", :id, "--cpus", "2"]
        end
        dnsserver.vm.synced_folder ".", "/vagrant", disabled: true
    end

    config.vm.provision "ansible" do |ansible|
        ansible.verbose = "v"
        ansible.playbook = "playbook.yml"
        ansible.extra_vars = {
            attacker_ip: ATTACKER_IP,
            attacker_domain: ATTACKER_DOMAIN,
            attacker_tld: ATTACKER_TLD,
            stealthyvec_tld: STEALTHYVEC_TLD,
            dns_server_ip: DNS_SERVER_IP,
            record_type: RECORD_TYPE,
            response_address: RESPONSE_ADDRESS
        }
        ansible.host_vars = {
            "attacker" => {
                "ansible_python_interpreter" => "/usr/bin/python3"
            },
            "dnsserver" => {
                "ansible_python_interpreter" => "/usr/bin/python3"
            }
        }
    end

end