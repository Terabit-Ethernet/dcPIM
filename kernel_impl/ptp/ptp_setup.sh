source env.sh
sudo killall ptp4l phc2sys
sudo timedatectl set-ntp false
sudo ptp4l -i $INTF -f gPTP.cfg --step_threshold=1 &
sleep 15

sudo pmc -u -b 0 -t 1 "SET GRANDMASTER_SETTINGS_NP clockClass 248 \
        clockAccuracy 0xfe offsetScaledLogVariance 0xffff \
        currentUtcOffset 37 leap61 0 leap59 0 currentUtcOffsetValid 1 \
        ptpTimescale 1 timeTraceable 1 frequencyTraceable 0 \
        timeSource 0xa0"
sudo phc2sys -s $INTF -c CLOCK_REALTIME --step_threshold=1 \
        --transportSpecific=1 -w &
