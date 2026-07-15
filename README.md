## Usage
``` bash
-endpoint       OPC-UA Endpoint
-ip             OPC-UA Server IP
-ports          OPC-UA Server Port
-ip_file        new line deliminated file of IPs. Can also specify ports. See examples for more
-probe-anon     attempt to connect with Anonymous credentials to confirm if access really works
-probe-creds    attempt to connect with provided credentials to check if they work (requires username and password to be specified)
-username   
-password
-probe-write    scan the endpoint for writeable tags
-rewrite-host   if the server is behind NAT/Firewall, use this to replace the local address with the advertised one
```

### Examples

Scan an OPC-UA Server by endpoint

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840"`


Scan an OPC-UA Server by IP

`go run opcua_recon.go -ip "10.0.0.10"`


Scan an OPC-UA Server by IP and non-standard port

`go run opcua_recon.go -ip "10.0.0.10" -port 18889`


Scan an OPC-UA Server by Endpoint and check in anonymous access works

`go run opcua_recon.go -endpoint "opc.tcp://10.0.0.10:4840" -probe-anon`

