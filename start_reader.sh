sudo systemctl start pcscd
sudo systemctl enable pcscd
echo "blacklist pn533_usb" | sudo tee -a /etc/modprobe.d/blacklist-libnfc.conf
