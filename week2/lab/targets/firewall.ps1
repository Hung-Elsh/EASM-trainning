# Lets ONLY Kali reach the SecLab targets. Run in PowerShell as Administrator:
#   powershell -ExecutionPolicy Bypass -File .\firewall.ps1
# Add any new published port to the lists below and run this again.
$Kali  = "192.168.1.249"
$TcpPorts = @("21","22","23","25","53","80","110","143","443","465","587","993","995","1433",
              "2222","2375","2376","2379","3000","3306","3389","5432","5900","6379","6443",
              "8000","8009","8080","8081","8082","8443","8888","9000","9090","9200","10250",
              "11211","27017","30000-30009")
$UdpPorts = @("53","123","161","11211")

# Everything except Kali, IPv4 and IPv6 (Docker also publishes ports on IPv6)
$Others = @("0.0.0.0-192.168.1.248", "192.168.1.250-255.255.255.255",
            "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

Remove-NetFirewallRule -DisplayName "SecLab targets (Kali only)" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "SecLab targets (block others)" -ErrorAction SilentlyContinue

foreach ($rule in @(@("TCP", $TcpPorts), @("UDP", $UdpPorts))) {
  New-NetFirewallRule -DisplayName "SecLab targets (Kali only)" -Direction Inbound -Protocol $rule[0] `
    -LocalPort $rule[1] -RemoteAddress $Kali -Action Allow -Profile Private | Out-Null

  # A block rule beats every allow rule, so this still protects you if Docker Desktop
  # re-creates its allow-all rules after an update.
  New-NetFirewallRule -DisplayName "SecLab targets (block others)" -Direction Inbound -Protocol $rule[0] `
    -LocalPort $rule[1] -RemoteAddress $Others -Action Block -Profile Any | Out-Null
}

Get-NetFirewallRule -DisplayName "SecLab targets*" | ForEach-Object {
  "{0} {1}: {2}, profile {3}, remote {4}" -f $_.DisplayName, ($_ | Get-NetFirewallPortFilter).Protocol,
    $_.Action, $_.Profile, (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ", ")
}
Get-NetConnectionProfile | ForEach-Object { "Network {0}: {1}" -f $_.InterfaceAlias, $_.NetworkCategory }
