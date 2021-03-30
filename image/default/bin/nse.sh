#! /bin/sh
##
## template.sh --
##
##
## Commands;
##

prg=$(basename $0)
dir=$(dirname $0); dir=$(readlink -f $dir)
tmp=/tmp/${prg}_$$
me=$dir/$prg

die() {
    echo "ERROR: $*" >&2
    rm -rf $tmp
    exit 1
}
help() {
    grep '^##' $0 | cut -c3-
    rm -rf $tmp
    exit 0
}
test -n "$1" || help
echo "$1" | grep -qi "^help\|-h" && help

log() {
	echo "$prg: $*" >&2
}
dbg() {
	test -n "$__verbose" && echo "$prg: $*" >&2
}

##  env
##    Print environment.
##
cmd_env() {
	test "$cmd" = "env" && set | grep -E '^(__.*|ARCHIVE)='
	return 0
}

## Callout functions;
##  init
##    Called at startup
##  request
##    Expects a NSM-request in json format on stdin.
##  close
##    Expects a NSM-request in json format on stdin.
##  mechanism
##    Produce a networkservice.Mechanism mechanism array in json format
##    on stdout
##

cmd_init() {
	return 0
}

# For now we must return a mechanism of any type and only
# parameters.name will be handled.
cmd_mechanism() {
	cat <<EOF
[
  {
    "cls": "REMOTE",
    "type": "KERNEL",
    "parameters": {
      "name": "nse$RANDOM"
    }
  }
]
EOF
}

cmd_request() {
	# json is global
	json=/tmp/connection.json
	jq 'del(.connection.path)' > $json
	cat $json
}

cmd_close() {
	# json is global
	json=/tmp/connection.json
	jq 'del(.connection.path)' > $json
	cat $json
}


# Get the command
cmd=$1
shift
grep -q "^cmd_$cmd()" $0 $hook || die "Invalid command [$cmd]"

while echo "$1" | grep -q '^--'; do
    if echo $1 | grep -q =; then
	o=$(echo "$1" | cut -d= -f1 | sed -e 's,-,_,g')
	v=$(echo "$1" | cut -d= -f2-)
	eval "$o=\"$v\""
    else
	o=$(echo "$1" | sed -e 's,-,_,g')
	eval "$o=yes"
    fi
    shift
done
unset o v
long_opts=`set | grep '^__' | cut -d= -f1`

# Execute command
trap "die Interrupted" INT TERM
cmd_$cmd "$@"
status=$?
rm -rf $tmp
exit $status
