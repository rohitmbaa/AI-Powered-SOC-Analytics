-- Top source IPs by failed authentication volume
SELECT source_ip, COUNT(*) AS failed_attempts
FROM authentication_logs
WHERE login_status = 'Failure'
GROUP BY source_ip
ORDER BY failed_attempts DESC;

-- Highest outbound transfer events
SELECT timestamp, source_ip, destination_ip, bytes_out
FROM firewall_logs
WHERE bytes_out >= 500000000
ORDER BY bytes_out DESC;

-- Suspicious PowerShell events
SELECT timestamp, username, host, command_line
FROM endpoint_logs
WHERE LOWER(process) = 'powershell.exe'
  AND LOWER(command_line) LIKE '%encodedcommand%';
