sudo apt-get remove linuxptp
git clone http://git.code.sf.net/p/linuxptp/code linuxptp
cd linuxptp/
make
sudo apt-get install checkinstall
sudo checkinstall

# remove ptp package
# dpkg -r linux_ptp
