define ufw::allow($proto="any", $port="any", $to="any", $from="any") {

  ######################################################
  # "ufw status" rules matching
  ######################################################

  # Special case: if you allow from any to any with
  # a proto, you'll get this. We shouldn't have this
  # rule, though
  #
  #Anywhere/tcp               ALLOW       Anywhere/tcp

  #Anywhere                   ALLOW       Anywhere
  #19823                      ALLOW       Anywhere
  #19823/tcp                  ALLOW       Anywhere
  #Anywhere                   ALLOW       192.168.1.2/tcp
  #192.168.1.1                ALLOW       Anywhere
  #192.168.1.1 12345          ALLOW       Anywhere
  #192.168.1.1 12345/tcp      ALLOW       Anywhere
  #192.168.1.1/tcp            ALLOW       Anywhere
  if ( $to == "any" ) and ( $port == "any" ) {
    $match_to_proto = ""
  } else {
    $match_to_proto = $proto ? {
      "any"   => "",
      default => "/${proto}",
    }
  }
  $match_to_port = $port ? {
    "any"   => "",
    default => " *${port}",
  }
  $match_to_to = $to ? {
    "any"   => "Anywhere",
    default => $to,
  }
  $match_to = "${match_to_to}${match_to_port}${match_to_proto}"

  #Anywhere                   ALLOW       Anywhere
  #Anywhere                   ALLOW       12345
  #Anywhere                   ALLOW       12345/tcp
  #192.168.1.1/tcp            ALLOW       Anywhere
  #Anywhere                   ALLOW       192.168.1.2
  #Anywhere                   ALLOW       192.168.1.2 12345
  #Anywhere                   ALLOW       192.168.1.2 12345/tcp
  #Anywhere                   ALLOW       192.168.1.2/tcp
  if ( $from == "any" ) and ( $port == "any" ) {
    $match_from_proto = ""
  } else {
    $match_from_proto = $proto ? {
      "any"   => "",
      default => "/${proto}",
    }
  }
  $match_from_port = $port ? {
    "any"   => "",
    default => " *${port}",
  }
  $match_from_from = $from ? {
    "any"   => "",
    default => $from,
  }
  $match_from = "${match_from_to}${match_from_port}${match_from_proto}"

  $match_line = "${match_to} +ALLOW +${match_from}"
  
  notify { $match_line:;}

  exec { "ufw-allow-$proto-from-$from-to-$to-port-$port":
    command => $port ? {
      "any" => "ufw allow proto $proto from $from to $to",
      default => "ufw allow proto $proto from $from to $to port $port",
    },
    unless => "ufw status | grep -E \"${match_line}\"",
    require => Exec["ufw-default-deny"],
    before => Exec["ufw-enable"],
  }
}
