CREATE TABLE authentication_logs (
    event_id VARCHAR(20) PRIMARY KEY,
    timestamp TIMESTAMP,
    user_id VARCHAR(20),
    username VARCHAR(100),
    department VARCHAR(100),
    host VARCHAR(50),
    source_ip VARCHAR(50),
    country VARCHAR(50),
    login_status VARCHAR(20),
    authentication_method VARCHAR(50)
);

CREATE TABLE firewall_logs (
    event_id VARCHAR(20) PRIMARY KEY,
    timestamp TIMESTAMP,
    source_ip VARCHAR(50),
    destination_ip VARCHAR(50),
    protocol VARCHAR(10),
    destination_port INT,
    action VARCHAR(20),
    bytes_out BIGINT
);

CREATE TABLE endpoint_logs (
    event_id VARCHAR(20) PRIMARY KEY,
    timestamp TIMESTAMP,
    user_id VARCHAR(20),
    username VARCHAR(100),
    host VARCHAR(50),
    process VARCHAR(100),
    parent_process VARCHAR(100),
    command_line TEXT,
    severity VARCHAR(20)
);
