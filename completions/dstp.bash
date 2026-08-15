# bash completion for dstp
_dstp_checks="ping dns configured_dns records mail dnssec tcp udp tls http https http3 cdn traceroute whois mtu"

_dstp() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local opts="-a --addr -o --out -p -t --port --tcp-port --udp-port --http-port --dns --doh --doh-url --doh-format --doh-bootstrap --method --follow-redirects --insecure --extra --profile --skip --config -q --quiet -v --version -h --help"
  case "${prev}" in
    -o|--out) COMPREPLY=( $(compgen -W "plaintext json" -- "${cur}") ); return ;;
    --method) COMPREPLY=( $(compgen -W "GET HEAD" -- "${cur}") ); return ;;
    --doh-format) COMPREPLY=( $(compgen -W "rfc8484 json" -- "${cur}") ); return ;;
    --profile) COMPREPLY=( $(compgen -W "web mail dns api full" -- "${cur}") ); return ;;
    --skip)
      local prefix="" rest="${cur}"
      if [[ "${cur}" == *,* ]]; then
        prefix="${cur%,*},"
        rest="${cur##*,}"
      fi
      local comps
      comps=$(compgen -W "${_dstp_checks}" -- "${rest}")
      COMPREPLY=()
      local c
      for c in ${comps}; do
        COMPREPLY+=("${prefix}${c}")
      done
      return
      ;;
  esac
  if [[ "${cur}" == -* ]]; then
    COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
  fi
}
complete -F _dstp dstp
