# bash completion for dstp
_dstp() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local opts="-a --addr -o --out -p -t --port --tcp-port --udp-port --http-port --dns --doh --doh-url --method --follow-redirects --insecure --extra --skip --config -q --quiet -v --version -h --help"
  case "${prev}" in
    -o|--out) COMPREPLY=( $(compgen -W "plaintext json" -- ${cur}) ); return ;;
    --method) COMPREPLY=( $(compgen -W "GET HEAD" -- ${cur}) ); return ;;
    --skip) COMPREPLY=( $(compgen -W "ping dns configured_dns records tcp udp tls http https traceroute whois mtu" -- ${cur}) ); return ;;
  esac
  COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
}
complete -F _dstp dstp
