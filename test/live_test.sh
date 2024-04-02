#!/bin/sh
#
# see README-testing for more information
# do some basic booth operation tests for the given config
#

PROG=`basename $0`
usage() {
	cat<<EOF
usage:

	[NETEM_ENV=<envfun>[:<val>]] $PROG <booth.conf> [<test> ...]

EOF
	if [ $1 -eq 0 ]; then
		list_all
		examples
	fi
	exit
}

list_all() {
	echo "Tests:"
	grep "^test_.*{$" $0 | sed 's/test_//;s/(.*//;s/^/	/'
	echo
	echo "Netem functions:"
	grep "^NETEM_ENV_.*{$" $0 | sed 's/NETEM_ENV_//;s/(.*//;s/^/	/'
}
examples() {
	cat<<EOF

Examples:

	$0 booth.conf
	$0 booth-5node.conf grant revoke
	NETEM_ENV=net_delay:150 $0 mybooth.conf

EOF
}

[ $# -eq 0 ] && usage 0

cnf=$1
run_cnf="/etc/booth/booth.conf"

shift 1
ERR_SETUP_FAILED=52
logf=test_booth.log
SSH_OPTS="-o StrictHostKeyChecking=no -l root"
iprules=/usr/share/booth/tests/test/booth_path
: ${HA_LOGFACILITY:="syslog"}

get_site() {
	local n=$1
	echo $sites | awk '{print $'$n'}'
}
get_internal_site() {
	local n=$1
	echo $internal_sites | awk '{print $'$n'}'
}

logmsg() {
	if [ "$WE_SERVER" -o "$_JUST_NETEM" ]; then
		logger -t "BOOTHTEST" -p $HA_LOGFACILITY.info -- "$@"
	else
		ssh $SSH_OPTS `get_site 1` logger -t "BOOTHTEST" -p $HA_LOGFACILITY.info -- "$@"
	fi
}

ext_prog_log() {
	local cmd="$@"
	echo "run: $cmd" | logmsg
	$cmd
}
get_stat_fld() {
	local fld=$1
	sed "s/.* $fld=//;s/ .*//;s/'//g"
}

# tc netem, simulate packet loss, wan, etc
netem_parent() {
	local p
	p=`tc qdisc show dev $1 | grep netem | head -1 | awk '{print $3}'`
	if [ -n "$p" ]; then
		echo $p
	else
		echo 1:1
	fi
}
tc_prio() {
	ext_prog_log tc qdisc add dev $1 handle 1: root prio
	ext_prog_log tc filter add dev $1 parent 1: prio 1 u32 \
	        match ip dport $port 0xffff \
			match ip protocol 17 0xff \
			flowid 1:1
}
netem_delay() {
	ext_prog_log tc qdisc add dev $1 parent `netem_parent $1` netem delay $2ms $(($2/10))ms
}
netem_duplicate() {
	ext_prog_log tc qdisc add dev $1 parent `netem_parent $1` \
		netem duplicate $2\%
}
netem_reorder() {
	ext_prog_log tc qdisc add dev $1 parent `netem_parent $1` \
		netem reorder $2\% $3\% delay 10ms
}
netem_loss() {
	ext_prog_log tc qdisc add dev $1 parent `netem_parent $1` netem loss $2%
}
netem_reset() {
	ext_prog_log tc qdisc del dev $1 root
}
local_netem_env() {
	local fun=$1
	shift 1
	local args=$*
	local t netif=""
	local my_addr
	my_addr=`booth status | get_stat_fld booth_addr_string`
	if [ -z "$my_addr" ]; then
		logmsg "cannot find my address, booth running?"
		return 1
	fi
	for t in `ip link | grep '^[1-9]:' | sed 's/.: //;s/: .*//'`
	do
		if ip a l $t | fgrep -wq $my_addr; then
			netif=$t
			break
		fi
	done
	if [ -n "$netif" ]; then
		# before first netem qdisc insert the prio qdisc and filter
		tc qdisc show dev $netif | grep -qs netem ||
			tc_prio $netif
		$fun $netif $args
	else
		logmsg "cannot find netif for $my_addr, netem not set"
	fi
}

is_function() {
	test z"`command -v $1`" = z"$1"
}
runcmd() {
	local h=$1 rc
	shift 1
	echo "$h: running '$*'" | logmsg
	if ip a l | fgrep -wq $h; then
		eval "$@"
	else
		ssh $SSH_OPTS $h "$@"
	fi
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "$h: '$*' failed (exit code $rc)" | logmsg
	fi
	return $rc
}
manage_site() {
	runcmd $1 crm -w resource $2 booth
}
manage_arbitrator() {
	if ps 1 | grep -qws systemd; then
		runcmd $1 systemctl $2 booth@booth.service
	else
		runcmd $1 rcbooth-arbitrator $2
	fi
}
start_site() {
	manage_site $1 start
}
start_arbitrator() {
	manage_arbitrator $1 start
}
stop_site_clean() {
	manage_site $1 stop &&
	#sleep 1 &&
	runcmd $1 crm_ticket --force -t $tkt --cleanup > /dev/null
}
stop_site() {
	manage_site $1 stop
}
stop_arbitrator() {
	manage_arbitrator $1 stop
}
restart_site() {
	manage_site $1 restart
}
cleanup_site() {
	manage_site $1 cleanup
}
reload_site() {
	runcmd $1 OCF_ROOT=/usr/lib/ocf /usr/lib/ocf/resource.d/pacemaker/booth-site reload
}
restart_arbitrator() {
	manage_arbitrator $1 restart
}
booth_status() {
	test "`runcmd $1 booth status | get_stat_fld booth_state`" = "started"
}
cleanup_booth() {
	local h procs
	for h in $sites; do
		cleanup_site $h & procs="$! $procs"
	done >/dev/null 2>&1
	wait $procs
	wait_timeout
}
cleanup_dep_rsc() {
	local dep_rsc=`get_rsc`
	test -z "$dep_rsc" && return
	local h procs
	for h in $sites; do
		runcmd $h crm -w resource cleanup $dep_rsc & procs="$! $procs"
	done >/dev/null 2>&1
	wait $procs
}
check_dep_rsc() {
	local dep_rsc=`get_rsc`
	test -z "$dep_rsc" && return 0
	local h
	for h in $sites; do
		runcmd $h BOOTH_TICKET=$tkt /usr/share/booth/service-runnable $dep_rsc ||
			return 1
	done
	return 0
}
stop_booth() {
	local h rc
	for h in $sites; do
		stop_site $h
		rc=$((rc|$?))
	done >/dev/null 2>&1
	for h in $arbitrators; do
		stop_arbitrator $h
		rc=$((rc|$?))
	done >/dev/null 2>&1
	wait_timeout
	return $rc
}
start_booth() {
	local h rc
	for h in $sites; do
		start_site $h
		rc=$((rc|$?))
	done >/dev/null 2>&1
	for h in $arbitrators; do
		start_arbitrator $h
		rc=$((rc|$?))
	done >/dev/null 2>&1
	wait_timeout
	return $rc
}
restart_booth() {
	local h procs
	for h in $sites; do
		restart_site $h & procs="$! $procs"
	done >/dev/null 2>&1
	for h in $arbitrators; do
		restart_arbitrator $h
	done >/dev/null 2>&1
	wait $procs
	wait_timeout
}
reboot_test() {
	cleanup_booth
	restart_booth
	cleanup_dep_rsc
}
is_we_server() {
	local h
	for h in $sites $arbitrators; do
		ip a l | fgrep -wq $h && return
	done
	return 1
}
is_pacemaker_running() {
	local h
	for h in $sites; do
		runcmd $h crmadmin -D >/dev/null || return 1
	done
	return 0
}
sync_conf() {
	local h rc=0
	local tmpf
	for h in $sites $arbitrators; do
		rsync -q -e "ssh $SSH_OPTS" $1 root@$h:$run_cnf
		rc=$((rc|$?))
		if [ -n "$authfile" ]; then
			tmpf=`mktemp`
			scp -q $(get_site 1):$authfile $tmpf &&
			rsync -q -e "ssh $SSH_OPTS" $tmpf root@$h:$authfile
			rc=$((rc|$?))
			rm -f $tmpf
		fi
	done
	return $rc
}
dump_conf() {
	echo "test configuration file $cnf:"
	grep -v '^#' $cnf | grep -v '^[[:space:]]*$' | sed "s/^/$cnf: /"
}
forall() {
	local h rc=0
	for h in $sites $arbitrators; do
		runcmd $h "$@"
		rc=$((rc|$?))
	done
	return $rc
}
forall_withname() {
	local h rc=0 output
	for h in $sites $arbitrators; do
		output=`runcmd $h "$@"`
		rc=$((rc|$?))
		echo $h: $output
	done
	return $rc
}
forall_sites() {
	local h rc=0
	for h in $sites; do
		runcmd $h "$@"
		rc=$((rc|$?))
	done
	return $rc
}
forall_fun() {
	local h rc=0 f=$1
	for h in $sites $arbitrators; do
		$f $h
		rc=$((rc|$?))
		[ $rc -ne 0 ] && break
	done
	return $rc
}
# run on all hosts whatever function produced on stdout
forall_fun2() {
	local h rc=0 f
	f=$1
	shift 1
	for h in $sites $arbitrators; do
		$f "$@" | ssh $SSH_OPTS $h
		rc=$((rc|$?))
		[ $rc -ne 0 ] && break
	done
	return $rc
}
run_site() {
	local n=$1 h
	shift 1
	h=`echo $sites | awk '{print $'$n'}'`
	runcmd $h "$@"
}
run_arbitrator() {
	local n=$1 h
	shift 1
	h=`echo $arbitrators | awk '{print $'$n'}'`
	runcmd $h "$@"
}

# need to get logs from _all_ clusters' nodes
get_all_nodes() {
	for h in $sites; do
		runcmd $h crm_node -l | awk '{print $2}'
	done
}
extract_value() {
	sed 's/ *#.*//;s/.*=//;s/"//g;s/^ *//;s/ *$//'
}
get_extern_ip() {
	grep "^$1" |
		awk '
		{ if(/#  *external[_-]ip=/) print $NF; else print; }
		' | extract_value
}
get_value() {
	grep "^$1" | extract_value
}
# get internal IP for the external address
internal_ip() {
	fgrep "$1" $cnf | extract_value
}
get_rsc() {
	awk '
n && /^[[:space:]]*before-acquire-handler/ {print $NF; exit}
n && (/^$/ || /^ticket.*/) {exit}
/^ticket.*'$tkt'/ {n=1}
' $cnf
}
get_attr() {
	awk '
n && /^[[:space:]]*attr-prereq = auto .* eq / {print $4,$6; exit}
n && (/^$/ || /^ticket.*/) {exit}
/^ticket.*'$tkt'/ {n=1}
' $cnf
}
get_mode() {
	awk '
n && /^[[:space:]]*mode/ {print $NF; exit}
n && (/^$/ || /^ticket.*/) {exit}
/^ticket.*'$tkt'/ {n=1}
' $cnf
}

set_site_attr() {
	local site
	site=$1
	set -- `get_attr`
	run_site $site geostore set $1 $2
}
del_site_attr() {
	local site
	site=$1
	set -- `get_attr`
	run_site $site geostore delete $1
}
break_external_prog() {
	run_site $1 crm configure "location $PREFNAME `get_rsc` rule -inf: defined \#uname"
}
show_pref() {
	run_site $1 crm configure show $PREFNAME > /dev/null
}
repair_external_prog() {
	run_site $1 crm configure delete __pref_booth_live_test
}
get_tkt() {
	grep "^ticket=" | head -1 | sed 's/ticket=//;s/"//g'
}
get_tkt_settings() {
awk '
n && /^[[:space:]]*(expire|timeout|renewal-freq)/ {
	sub(" = ", "=", $0);
	gsub("-", "_", $0);
	sub("^[[:space:]]*", "T_", $0);
	if ($0 ~ /ms$/) {
		sub("ms$", "", $0);
		eq = match($0, "=");
		print substr($0, 1, eq)""substr($0, eq+1)/1000;
	} else {
		print;
	}
	next
}
n && (/^$/ || /^ticket.*/) {exit}
/^ticket.*'$tkt'/ {n=1}
' $1
}
wait_exp() {
	# shellcheck disable=SC2154
	# (T_expire: defined with get_tkt_settings)
	sleep $T_expire
}
wait_renewal() {
	sleep $T_renewal_freq
}
wait_timeout() {
	sleep $MIN_TIMEOUT
}

set_netem_env() {
	local modfun args
	modfun=`echo $1 | sed 's/:.*//'`
	args=`echo $1 | sed 's/[^:]*//;s/:/ /g'`
	if ! is_function NETEM_ENV_$modfun; then
		echo "NETEM_ENV_$modfun: doesn't exist"
		exit 1
	fi
	NETEM_ENV_$modfun $args
}
reset_netem_env() {
	[ -z "$NETEM_ENV" ] && return
	[ -n "$__NETEM_RESET" ] && return
	__NETEM_RESET=1
	forall $ABSPATH $run_cnf __netem__ netem_reset
}
setup_netem() {
	[ -z "$NETEM_ENV" ] && return
	__NETEM_RESET=
	echo "-------------------------------------------------- (netem)" | logmsg
	for env in $NETEM_ENV; do
		set_netem_env $env
	done
	trap "reset_netem_env" EXIT
}

cib_status() {
	local h=$1 stat
	stat=`runcmd $h crm_ticket -L |
		grep "^$tkt" | awk '{print $2}'`
	test "$stat" != "-1"
}
is_cib_granted() {
	local stat h=$1
	stat=`runcmd $h crm_ticket -L |
		grep "^$tkt" | awk '{print $2}'`
	[ "$stat" = "granted" ]
}
check_cib_consistency() {
	local h gh="" rc=0
	for h in $sites; do
		if is_cib_granted $h; then
			[ -n "$gh" ] && rc=1 # granted twice
			gh="$gh `internal_ip $h`"
		fi
	done
	[ -z "$gh" ] && gh="none"
	if [ $rc -eq 0 ]; then
		echo $gh
		return $rc
	fi
	cat<<EOF | logmsg
CIB consistency test failed
ticket granted to $gh
EOF
	return $rc
}
check_cib() {
	local exp_grantee cib_grantee booth_grantee
	local rc=0 pending
	exp_grantee=$1
	booth_grantee=`booth_where_granted`
	pending=$?
	cib_grantee=`check_cib_consistency`
	if [ $pending -eq 0 ]; then
		[ "$cib_grantee" = "$booth_grantee" ]
		rc=$?
	else
		# ticket is not committed to cib yet
		[ "$exp_grantee" = "$booth_grantee" ]
		rc=$?
		exp_grantee="" # cheat a bit
	fi
	case "$exp_grantee" in
	"any") [ "$cib_grantee" != "none" ] ;;
	"") [ "$cib_grantee" = "none" ] ;;
	*) [ "$cib_grantee" = "$exp_grantee" ] ;;
	esac
	rc=$((rc|$?))
	if [ $rc -ne 0 ]; then
		cat<<EOF | logmsg
CIB check failed
CIB grantee: $cib_grantee
booth grantee: $booth_grantee
expected grantee: $exp_grantee
EOF
	fi
	return $rc
}

booth_where_granted() {
	local grantee ticket_line
	# we don't know which sites could be stopped, so run booth
	# list on all of them (at least one should have booth
	# running)
	ticket_line=`forall_sites booth list | grep $tkt | sort -u | head -1`
	grantee=`echo "$ticket_line" | sed 's/.*leader: //;s/,.*//;s/NONE/none/'`
	echo $grantee
	[ "$grantee" = "none" ] && return
	! echo "$ticket_line" | grep -q "$tkt.*pending"
}
booth_list_fld() {
	cut -d, -f $1 | sed 's/[^:]*://'
}
max_booth_time_diff() {
	local l
	booth_list_fld 3 |
	while read l; do
		date -d "$l" "+%s"
	done |
	awk '
	{t[n++]=$0}
	END{
		for (i=0; i<n; i++)
			for (j=i+1; j<n; j++) {
				x=t[i]-t[j];
				print x >= 0 ? x : -x;
			}
	}
	' | sort -n | tail -1
}
booth_leader_consistency() {
	test `booth_list_fld 2 | sort -u | wc -l` -eq 1
}
# are there two leaders or is it just that some booths are outdated
booth_leader_consistency_2() {
	test `booth_list_fld 2 | sort -u | grep -iv none | wc -l` -le 1
}
# do all booths have the same info?
# possible differences:
# a) more than one leader
# b) some booths not uptodate (have no leader for the ticket)
# c) ticket expiry times differ
check_booth_consistency() {
	local tlist rc rc_lead maxdiff
	tlist=`forall_withname booth list 2>/dev/null | grep $tkt`

	# Check time consistency
	ticket_times=$(echo "$tlist" | booth_list_fld 3)
	if [[ $ticket_times == *"INF"* ]]; then
		rc=0
	else
		maxdiff=`echo "$tlist" | max_booth_time_diff`
		test "$maxdiff" -eq 0
		rc=$?
	fi

	# Check leader consistency
	echo "$tlist" | booth_leader_consistency
	rc_lead=$?
	if [ $rc_lead -ne 0 ]; then
		echo "$tlist" | booth_leader_consistency_2
		rc_lead=$(($rc_lead + $?))  # rc_lead=2 if the prev test failed
	fi

	rc=$(($rc | $rc_lead<<1))
	test $rc -eq 0 && return
	cat<<EOF | logmsg
`if [ $rc -ge 4 ]; then
	echo "booth list consistency failed (more than one leader!):"
elif [ $rc -ge 2 ]; then
	echo "booth list consistency failed (some booths not up-to-date):"
else
	echo "booth list consistency failed (max valid time diff: $maxdiff):"
fi`
===========
"$tlist"
===========
EOF
	test $rc -le 1
}

check_consistency() {
	local rc
	local exp_grantee=$1
	check_booth_consistency
	rc=$?
	check_cib $exp_grantee
	return $((rc|$?))
}

all_booth_status() {
	forall_fun booth_status
}

can_run_test() {
	if is_function applicable_$1; then
		if ! applicable_$1; then
			echo "(not applicable, skipping)"
			return 1
		fi
	fi
	if ! is_function test_$1 || ! is_function check_$1; then
		echo "(test missing)"
		return 1
	fi
}
revoke_ticket() {
	run_site 1 booth revoke -w $tkt >/dev/null
	wait_timeout
}
run_report() {
	local start_ts=$1 end_ts=$2 name=$3
	local hb_report_opts=""
	local quick_opt=""
	logmsg "running hb_report"
	hb_report -Q 2>&1 | grep -sq "illegal.option" ||
		quick_opt="-Q"
	if [ `id -u` != 0 ]; then
		hb_report_opts="-u root"
	fi
	hb_report $hb_report_opts $quick_opt -f "`date -d @$((start_ts-5))`" \
		-t "`date -d @$((end_ts+60))`" \
		-n "$all_nodes $arbitrators" $name 2>&1 | logmsg
}
runtest() {
	local start_ts end_ts
	local rc booth_status dep_rsc_status
	local usrmsg
	rc=0
	TEST=$1
	start_ts=`date`  # to have the expanded form in the logfile
	start_ts=`date +%s`
	echo -n "Testing: $1 (ticket: $tkt)... "
	can_run_test $1 || return 0
	echo "==================================================" | logmsg
	echo "starting booth test $1 ..." | logmsg
	if is_function setup_$1; then
		echo "-------------------------------------------------- (setup)" | logmsg
		setup_$1
		rc=$?
		[ "$rc" -ne 0 ] && rc=$ERR_SETUP_FAILED
	fi
	if [ "$rc" -eq 0 ]; then
		setup_netem
		echo "-------------------------------------------------- (test)" | logmsg
		test_$1
		rc=$?
	fi
	case $rc in
	0)
		# wait a bit more if we're losing packets
		[ -n "$PKT_LOSS" ] && wait_timeout
		echo "-------------------------------------------------- (check)" | logmsg
		check_$1
		rc=$?
		if [ $rc -eq 0 ]; then
			usrmsg="SUCCESS"
		else
			usrmsg="check FAIL: $rc"
		fi
		;;
	$ERR_SETUP_FAILED)
		usrmsg="setup FAIL"
		;;
	*)
		usrmsg="test FAIL: $rc"
		;;
	esac
	end_ts=`date`  # to have the expanded form in the logfile
	end_ts=`date +%s`
	echo "finished booth test $1 ($tkt): $usrmsg" | logmsg
	echo "==================================================" | logmsg
	is_function recover_$1 && recover_$1
	reset_netem_env
	#sleep 3
	all_booth_status
	booth_status=$?
	check_dep_rsc
	dep_rsc_status=$?
	if [ $((rc|booth_status|dep_rsc_status)) -eq 0 ]; then
		echo OK
		[ "$GET_REPORT" ] && run_report $start_ts $end_ts $TEST
	else
		echo "$usrmsg (running hb_report ... $1.tar.bz2; see also $logf)"
		[ $booth_status -ne 0 ] &&
			echo "unexpected: some booth daemons not running"
		[ $dep_rsc_status -ne 0 ] &&
			echo "unexpected: dependent resource failure"
		run_report $start_ts $end_ts $TEST
		reboot_test
		master_rc=1
	fi
	revoke_ticket
}

#
# the tests
#

# most tests start by granting ticket
grant_ticket() {
	run_site $1 booth grant -w $tkt >/dev/null
}
grant_ticket_cib() {
	run_site $1 booth grant -C $tkt >/dev/null
}

## TEST: grant ##

# just a grant
test_grant() {
	grant_ticket 1
}
check_grant() {
	check_consistency `get_internal_site 1`
}

## TEST: longgrant ##

# just a grant followed by three expire times
setup_longgrant() {
	grant_ticket 1
}
test_longgrant() {
	wait_exp
	wait_exp
	wait_exp
}
check_longgrant() {
	check_consistency `get_internal_site 1`
}

## TEST: longgrant2 ##

# just a grant followed by 10 expire times
setup_longgrant2() {
	grant_ticket_cib 1
}
test_longgrant2() {
	local i
	# shellcheck disable=SC2034
	# (variable exists merely out of necessity)
	for i in `seq 10`; do
		wait_exp
	done
}
check_longgrant2() {
	check_consistency `get_internal_site 1`
}

## TEST: grant_noarb ##

# just a grant with no arbitrators
setup_grant_noarb() {
	local h
	for h in $arbitrators; do
		stop_arbitrator $h || return 1
	done >/dev/null 2>&1
	#sleep 1
}
test_grant_noarb() {
	grant_ticket 1
}
check_grant_noarb() {
	check_consistency `get_internal_site 1`
}
recover_grant_noarb() {
	local h
	for h in $arbitrators; do
		start_arbitrator $h
	done >/dev/null 2>&1
}
applicable_grant_noarb() {
	[ -n "$arbitrators" ]
}

## TEST: revoke ##

# just a revoke
setup_revoke() {
	grant_ticket 1
}
test_revoke() {
	revoke_ticket
}
check_revoke() {
	check_consistency
}

## TEST: grant_elsewhere ##

# just a grant to another site
test_grant_elsewhere() {
	run_site 1 booth grant -w -s `get_internal_site 2` $tkt >/dev/null
}
check_grant_elsewhere() {
	check_consistency `get_internal_site 2`
}

## TEST: grant_site_lost ##

# grant with one site lost
setup_grant_site_lost() {
	stop_site `get_site 2`
	booth_status `get_site 2` && return 1
	return 0
}
test_grant_site_lost() {
	grant_ticket 1
	wait_exp
}
check_grant_site_lost() {
	check_consistency `get_internal_site 1`
}
recover_grant_site_lost() {
	start_site `get_site 2`
}

## TEST: grant_site_reappear ##

# grant with one site lost then reappearing
setup_grant_site_reappear() {
	stop_site `get_site 2`
	booth_status `get_site 2` && return 1
	return 0
	#sleep 1
}
test_grant_site_reappear() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	check_cib `get_internal_site 1` || return $ERR_SETUP_FAILED
	wait_timeout
	start_site `get_site 2` || return $ERR_SETUP_FAILED
	wait_timeout
	wait_timeout
}
check_grant_site_reappear() {
	check_consistency `get_internal_site 1` &&
	is_cib_granted `get_site 1`
}
recover_grant_site_reappear() {
	start_site `get_site 2`
}

## TEST: simultaneous_start_even ##

# simultaneous start of even number of members
setup_simultaneous_start_even() {
	grant_ticket_cib 2 || return 1
	stop_booth || return 1
	#wait_timeout
}
test_simultaneous_start_even() {
	local serv
	for serv in $(echo $sites | sed "s/`get_site 1` //"); do
		start_site $serv &
	done
	for serv in $arbitrators; do
		start_arbitrator $serv &
	done
	wait_renewal
	start_site `get_site 1`
	wait_timeout
	wait_timeout
}
check_simultaneous_start_even() {
	check_consistency `get_internal_site 2`
}

## TEST: slow_start_granted ##

# slow start
setup_slow_start_granted() {
	grant_ticket_cib 1 || return 1
	stop_booth || return 1
	#wait_timeout
}
test_slow_start_granted() {
	for serv in $sites; do
		start_site $serv
		wait_timeout
	done
	for serv in $arbitrators; do
		start_arbitrator $serv
		wait_timeout
	done
}
check_slow_start_granted() {
	check_consistency `get_internal_site 1`
}

## TEST: restart_granted ##

# restart with ticket granted
setup_restart_granted() {
	grant_ticket_cib 1
}
test_restart_granted() {
	restart_site `get_site 1` || return 1
	wait_timeout
}
check_restart_granted() {
	check_consistency `get_internal_site 1`
}

## TEST: reload_granted ##

# reload with ticket granted
setup_reload_granted() {
	grant_ticket_cib 1
}
test_reload_granted() {
	reload_site `get_site 1` || return 1
	wait_timeout
}
check_reload_granted() {
	check_consistency `get_internal_site 1`
}

## TEST: restart_granted_nocib ##

# restart with ticket granted (but cib empty)
setup_restart_granted_nocib() {
	grant_ticket_cib 1
}
test_restart_granted_nocib() {
	stop_site_clean `get_site 1` || return 1
	#wait_timeout
	start_site `get_site 1` || return 1
	wait_timeout
	wait_timeout
	wait_timeout
}
check_restart_granted_nocib() {
	check_consistency `get_internal_site 1`
}

## TEST: restart_notgranted ##

# restart with ticket not granted
setup_restart_notgranted() {
	grant_ticket_cib 1
}
test_restart_notgranted() {
	stop_site `get_site 2` || return 1
	#sleep 1
	start_site `get_site 2` || return 1
	wait_timeout
}
check_restart_notgranted() {
	check_consistency `get_internal_site 1`
}

## TEST: failover ##

# ticket failover
setup_failover() {
	grant_ticket 1
	[ -n "`get_attr`" ] && set_site_attr 2
	return 0
}
test_failover() {
	stop_site_clean `get_site 1` || return 1
	booth_status `get_site 1` && return 1
	wait_exp
	wait_timeout
	wait_timeout
	wait_timeout
}
check_failover() {
	check_consistency any
}
recover_failover() {
	start_site `get_site 1`
}

## TEST: split_leader ##

# split brain (leader alone)
setup_split_leader() {
	grant_ticket_cib 1
	[ -n "`get_attr`" ] && set_site_attr 2
	return 0
}
test_split_leader() {
	run_site 1 $iprules stop $port >/dev/null
	wait_exp
	wait_timeout
	wait_timeout
	wait_timeout
	wait_timeout
	check_cib any || return 1
	run_site 1 $iprules start $port >/dev/null
	wait_timeout
	wait_timeout
	wait_timeout
}
check_split_leader() {
	check_consistency any
}
recover_split_leader() {
	run_site 1 $iprules start $port >/dev/null
}

## TEST: split_follower ##

# split brain (follower alone)
setup_split_follower() {
	grant_ticket_cib 1
}
test_split_follower() {
	run_site 2 $iprules stop $port >/dev/null
	wait_exp
	wait_timeout
	run_site 2 $iprules start $port >/dev/null
	wait_timeout
}
check_split_follower() {
	check_consistency `get_internal_site 1`
}

## TEST: split_edge ##

# split brain (leader alone)
setup_split_edge() {
	grant_ticket_cib 1
}
test_split_edge() {
	run_site 1 $iprules stop $port >/dev/null
	wait_exp
	run_site 1 $iprules start $port >/dev/null
	wait_timeout
	wait_timeout
}
check_split_edge() {
	check_consistency any
}

## TEST: external_prog_failed ##

# external test prog failed
setup_external_prog_failed() {
	grant_ticket 1 || return 1
	[ -n "`get_attr`" ] && set_site_attr 2
	break_external_prog 1
	show_pref 1 || return 1
}
test_external_prog_failed() {
	wait_renewal
	wait_timeout
}
check_external_prog_failed() {
	check_consistency any &&
	[ `booth_where_granted` != `get_internal_site 1` ]
}
recover_external_prog_failed() {
	repair_external_prog 1
}
applicable_external_prog_failed() {
	[ -n "`get_rsc`" ]
}

## TEST: attr_prereq_ok ##

# failover with attribute prerequisite
setup_attr_prereq_ok() {
	grant_ticket 1 || return 1
	set_site_attr 2
	stop_site_clean `get_site 1`
	booth_status `get_site 1` && return 1
	return 0
}
test_attr_prereq_ok() {
	wait_exp
	wait_timeout
}
check_attr_prereq_ok() {
	check_consistency `get_internal_site 2`
}
recover_attr_prereq_ok() {
	start_site `get_site 1`
	del_site_attr 2
}
applicable_attr_prereq_ok() {
	[ -n "`get_attr`" ]
}

## TEST: attr_prereq_fail ##

# failover with failed attribute prerequisite
setup_attr_prereq_fail() {
	grant_ticket 1 || return 1
	del_site_attr 2 >/dev/null 2>&1
	stop_site_clean `get_site 1`
	booth_status `get_site 1` && return 1
	return 0
}
test_attr_prereq_fail() {
	wait_exp
	wait_exp
	wait_exp
}
check_attr_prereq_fail() {
	check_consistency &&
	booth_where_granted | grep -qwi none
}
recover_attr_prereq_fail() {
	start_site `get_site 1`
}
applicable_attr_prereq_fail() {
	[ -n "`get_attr`" ]
}

## TEST: crmv1_group_start ##

add_crmv1_group() {
	crmv1 group testgrp rsc1 Dummy rsc2 Dummy fake=test
}

rm_crmv1_group() {
	crmv1 group delete testgrp
}

check_resources() {
	export OCF_ROOT=/usr/lib/ocf
	export OCF_RESOURCE_INSTANCE=rsc1
	. /usr/lib/ocf/lib/heartbeat/ocf-shellfuncs 
	/usr/lib/ocf/resource.d/heartbeat/Dummy monitor || return 1
	OCF_RESOURCE_INSTANCE=rsc2
	export OCF_RESKEY_fake=test
	/usr/lib/ocf/resource.d/heartbeat/Dummy monitor || return 1
	return 0
}

# crmv1 start a group
setup_crmv1_group_start_ok() {
	add_crmv1_group
}
test_crmv1_group_start_ok() {
	wait_exp
	wait_timeout
}
check_crmv1_group_start_ok() {
	check_resources
}
recover_crmv1_group_start_ok() {
	stop_site `get_site 1`
	stop_site `get_site 2`
	rm_crmv1_group
}

#
# environment modifications
#

# packet loss at one site 30%
NETEM_ENV_single_loss() {
	run_site 1 $ABSPATH $run_cnf __netem__ netem_loss ${1:-30}
	PKT_LOSS=${1:-30}
}

# packet loss everywhere 30%
NETEM_ENV_loss() {
	forall $ABSPATH $run_cnf __netem__ netem_loss ${1:-30}
	PKT_LOSS=${1:-30}
}

# network delay 100ms
NETEM_ENV_net_delay() {
	forall $ABSPATH $run_cnf __netem__ netem_delay ${1:-100}
}

# duplicate packets
NETEM_ENV_duplicate() {
	forall $ABSPATH $run_cnf __netem__ netem_duplicate ${1:-10}
}

# reorder packets
NETEM_ENV_reorder() {
	forall $ABSPATH $run_cnf __netem__ netem_reorder ${1:-25} ${2:-50}
}

# need this if we're run from a local directory or such
get_prog_abspath() {
	local p
	p=`run_site 1 rpm -ql booth-test | fgrep -w $PROG`
	echo ${p:-/usr/share/booth/tests/test/live_test.sh}
}

[ -f "$cnf" ] || {
	echo "ERROR: configuration file $cnf doesn't exist"
	usage 1
}
is_pacemaker_running || {
	echo "ERROR: sites must run pacemaker"
	exit 1
}

sites=`get_extern_ip site < $cnf`
arbitrators=`get_extern_ip arbitrator < $cnf`
internal_sites=`get_value site < $cnf`
internal_arbitrators=`get_value arbitrator < $cnf`
all_nodes=`get_all_nodes`
port=`get_value port < $cnf`
: ${port:=9929}

if [ "$1" = "__netem__" ]; then
	shift 1
	_JUST_NETEM=1
	local_netem_env "$@"
	exit
fi

[ -z "$internal_sites" ] && {
	echo no sites in $cnf
	usage 1
}

exec 2>$logf
BASH_XTRACEFD=2
PS4='+ `date +"%T"`: '
set -x

WE_SERVER=""
is_we_server && WE_SERVER=1

PREFNAME=__pref_booth_live_test

authfile=`get_value authfile < $cnf`
run_site 1 'test -f '"$authfile"' || booth-keygen '"$authfile"

TESTS="$@"
MANUAL_TESTS="$@"

: ${TESTS:="grant longgrant grant_noarb grant_elsewhere
grant_site_lost grant_site_reappear revoke
simultaneous_start_even slow_start_granted
restart_granted reload_granted restart_granted_nocib restart_notgranted
failover split_leader split_follower split_edge
external_prog_failed attr_prereq_ok attr_prereq_fail
crmv1_group_start"}

: ${MANUAL_TESTS:="grant longgrant grant_noarb grant_elsewhere
grant_site_lost
restart_granted reload_granted
split_leader split_follower split_edge
 "}

#get total number od lines in the file
conf_file_size=$(grep -c $ $cnf)

#get line numbers for all tickets
ticket_line_numbers=$(grep -n ticket $cnf | cut -d: -f1)
read -d'\n' -a TICKET_LINES<<< $ticket_line_numbers

#save the part of config located before ticket definitions
sed -n "1,$((${TICKET_LINES[0]}-1))p" $cnf > ${cnf}_main.config

#create a separate file for every ticket data
number_of_tickets=0
for i in $(seq 0 1 $((${#TICKET_LINES[@]}-1))); do
	ticket_line_start=${TICKET_LINES[i]}
	ticket_line_end=$((${TICKET_LINES[i+1]}-1))
	if [ ${ticket_line_end} -lt 0 ]; then
		# for the last ticket
		ticket_line_end=${conf_file_size}
	fi
	sed -n "${ticket_line_start},${ticket_line_end}p" $cnf > ${cnf}_${number_of_tickets}.ticket
	number_of_tickets=$((number_of_tickets+1))
done


master_rc=0 # updated in runtest

for i in `seq 0 $(($number_of_tickets-1))`
do
	cat ${cnf}_main.config > booth_${i}.conf
	cat ${cnf}_${i}.ticket >> booth_${i}.conf

	tkt=`get_tkt < booth_${i}.conf`

	if [ -z "$tkt" ]; then
		echo "Skipping empty ticket.."
		continue
	fi

	sync_conf booth_${i}.conf || exit
	reboot_test
	all_booth_status || {
		start_booth
		all_booth_status || {
			echo "some booth servers couldn't be started"
			exit 1
		}
	}

	ABSPATH=`get_prog_abspath`

	dump_conf | logmsg


	eval `get_tkt_settings booth_${i}.conf`

	# shellcheck disable=SC2154
	# (T_timeout: defined with get_tkt_settings)
	MIN_TIMEOUT=`awk -v tm=$T_timeout 'BEGIN{
			if (tm >= 2) print tm;
			else print 2*tm;
			}'`

	[ -z "$T_expire" ] && {
		echo set $tkt expire time in $cnf
		usage 1
	}

	if [ -z "$T_renewal_freq" ]; then
		T_renewal_freq=$((T_expire/2))
	fi

	revoke_ticket

	T_mode=`get_mode`
	T_mode_lowercase=$(echo "$T_mode" | tr '[:upper:]' '[:lower:]')

	if [[ $T_mode_lowercase == *"manual"* ]]; then
		echo "Running tests for manual tickets.."

		for t in $MANUAL_TESTS; do
			runtest $t
		done
	else
		echo "Running tests for automatic Raft tickets.."

		for t in $TESTS; do
			runtest $t
		done
	fi
done

exit $master_rc
