# Fedora install virtualization stack
sudo dnf install @virtualization

# For GUI use Boxes application from Gnome Software store

# !!!! Foreing VPN needed to overcome sanctions
# Install vagrant: https://developer.hashicorp.com/vagrant/install?product_intent=vagrant

# Don't forget to add user to libvirt group
usermod -G user libvirt

# Install libvirt vagrant plugin 
vagrant plugin install vagrant-libvirt

# Print return code
curl -s -o /dev/null -w "%{http_code}" https://localhost:3000/