bwlimit=2gbit
delay=0.1ms

sudo tc qdisc del dev lo root
sudo tc qdisc add dev lo root netem rate $bwlimit delay $delay

tc -s qdisc ls dev lo
