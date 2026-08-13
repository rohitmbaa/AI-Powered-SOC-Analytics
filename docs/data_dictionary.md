# Data Dictionary

## Authentication logs
- event_id: unique authentication event identifier
- timestamp: event timestamp
- user_id: synthetic user identifier
- user: synthetic username
- department: synthetic business department
- host: endpoint involved
- source_ip: source IP address
- country: synthetic geolocation label
- login_status: Success or Failure
- authentication_method: Password, MFA or SSO

## Firewall logs
- event_id: unique network event identifier
- timestamp: event timestamp
- source_ip: originating IP
- destination_ip: target IP
- protocol: TCP/UDP
- destination_port: destination service port
- action: ALLOW/DENY
- bytes_out: outbound byte count

## Endpoint logs
- event_id: unique endpoint event identifier
- timestamp: event timestamp
- user_id/user: synthetic identity
- host: endpoint
- process: process name
- parent_process: parent process
- command_line: synthetic command line
- severity: event severity

## Incidents
Synthetic incidents deliberately seeded for detection/investigation demonstrations.

## Security alerts
Detection alerts associated with seeded incidents.
