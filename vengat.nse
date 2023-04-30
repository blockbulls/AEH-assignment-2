description = [[
Attempts to find ip & the owner of an open TCP port &  Host status & other Addresses  & port status & Service on the target system.
]]
author = "Vengadesh"


-- portrule function to determine which ports to scan
portrule = function(host, port)
    local auth_port = { number=113, protocol="tcp" }
    local identd = nmap.get_port_state(host, auth_port)

    -- Only scan if identd is open on the target and the port being scanned is also open
    return identd ~= nil
           and identd.state == "open"
           and port.protocol == "tcp"
           and port.state == "open"
end

-- action function to perform the actual scan and get information about the owner of the port
action = function(host, port)
    local owner = ""

    -- create new socket objects for the identd and service connections
    local client_ident = nmap.new_socket()
    local client_service = nmap.new_socket()

    local catch = function()
        -- close both sockets in case of error
        client_ident:close()
        client_service:close()
    end

    local try = nmap.new_try(catch)

    -- connect to identd and service ports on the target
    try(client_ident:connect(host.ip, 113))
    try(client_service:connect(host.ip, port.number))

    -- get local IP and port of the service connection
    local localip, localport, remoteip, remoteport = client_service:get_info()

    -- send request to identd to get information about the port owner
    local request = port.number .. ", " .. localport .. "\r\n"
    try(client_ident:send(request))

    -- receive response from identd and extract the owner information
    owner = try(client_ident:receive_lines(1))
    if string.match(owner, "ERROR") then 
        owner = nil
    else
        owner = string.match(owner,
                             "%d+%s*,%s*%d+%s*:%s*USERID%s*:%s*.+%s*:%s*(.+)\r?\n")
    end

    -- close the sockets
    try(client_ident:close())
    try(client_service:close())

    return owner
end
