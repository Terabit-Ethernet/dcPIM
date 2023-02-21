source env.sh
gcc -o check_clocks check_clocks.c
sudo ./check_clocks -d $INTF
