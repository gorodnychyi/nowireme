#!/bin/sh
# nowireme emergency helper

## vars
daemon="wifidog"
sock1="/tmp/wdctl.sock"
server="https://nowire.me/firmware"
gw_id=`cat /etc/gw_id | tr -d ':'`
pid=`pgrep $daemon`
fstat="/tmp/node_status"
http_body="/tmp/http_body"
fcmd="/tmp/remotecmd.sh"
prev_stat=`[ -f /tmp/node_status ] && cat /tmp/node_status || echo "0"`
## statuses
# 0 - (endpoint /firmware/&gw_id=$gw_id&gw_status=$1) - all fine. send only if previous status was not 0
# 1 - (endpoint /firmware/&gw_id=$gw_id&gw_status=$1) - daemon down 1 check iteration && daemon restart && WARNING ALERT to admin
# 2 - (endpoint /firmware/&gw_id=$gw_id&gw_status=$1) - daemon down >1 check iteration && CRITICAL ALERT to admin && action needed
# 9 - (endpoint /firmware/&gw_id=$gw_id&gw_update=$1) - GET request for remote commands. expected reply "0" or encrypted command sequence
# 99 - or standard exit codes "http://tldp.org/LDP/abs/html/exitcodes.html" (endpoint /firmware/&gw_id=$gw_id&gw_update=$1) - report about remote command fail (99 = html body insted of encrypted command foud)

## helper functions
daemon_restart() {
	/etc/init.d/wifidog stop; sleep 3; /etc/init.d/wifidog start
}
send_alert() {
	curl -skL -o /dev/null $server/&gw_id=$gw_id&gw_status=$1
}
script_report() {
	curl -skL -o /dev/null $server/&gw_id=$gw_id&gw_update=$1
}
get_remote() {
	curl -skL -o $http_body $server/&gw_id=$gw_id&gw_update=$1
}

## actions
if [ -n "$pid" ] && [ -e $sock0 ]; then
	# if daemon is UP let's try to connect to
	# internal connection check
	wdctl status > /dev/nul
	OUT=$?
	if [ $OUT -eq 0 ]; then
		# all checks passed. node is up. cleanUp status file
		# if previous status was not 0, send report to server
		if [ $prev_stat -ne 0 ]; then
			send_alert 0
		fi
		echo $OUT > $fstat
	else
		# connection problems. trying to fix it by daemon restart. send alert to admin
		daemon_restart
		if [ $prev_stat -eq 0 ]; then
			echo "2" > $fstat
		else
			send_alert 2
		fi

	fi
else
	daemon_restart
	if [ $prev_stat -eq 0 ]; then
		send_alert 1
		echo "1" > $fstat
	else
		send_alert 2
	fi
fi

## custom actions (remote commands from server)
get_remote 9;
sleep 3;
if [ "$(wc -c $http_body | cut -f1 -d' ')" -gt 2 ]; then
# check if no html tags inside
	if [ -n $(head -1 $http_body |  grep "^<") ]; then
		rm -f $http_body;
		script_report 99
		exit
	fi
# decrypt command
	echo "#!/bin/sh" > $fcmd;
	echo "#######################" >> $fcmd;
	cat $http_body | openssl enc -aes-256-cbc -a -d -salt -pass pass:$gw_id >> $fcmd;
	chmod +x $fcmd;
	$fcmd;
	cat $fcmd 
	CMD_OUT=$?
	script_report $CMD_OUT
else
	exit
fi