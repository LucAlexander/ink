import "netinet.ink"
import "io.ink"

constant BUFFER_SIZE = 16000;

type Server = struct {
	i32 domain;
	u16 port;
	i32 service;
	i32 protocol;
	i32 backlog;
	i32 socket;
	sockaddr_in^ address; 
};

i32 -> u16 -> i32 -> i32 -> i32 -> u32 -> u64
server_init = \domain port service protocol backlog interface : {
	sockaddr_in_ink address = {
		sin_family = domain,
		sin_addr = {s_addr = htonl interface},
		sin_port = htons port
	};
	Server server = {
		domain, port, service, protocol, backlog,
		socket domain service protocol,
		(&(address as sockaddr_in))
	};
	if server.socket < 0 {
		print "Failed to initialize / connect to socket\n";
		return 0;
	};
	i32 bound = bind (server.socket) (server.address as u8^) ((sizeof sockaddr_in) as u32);
	if bound < 0 {
		print "Failed to bind socket\n";
		return 0;
	};
	i32 listening = listen (server.socket) (server.backlog);
	if listening < 0 {
		print "Failed to listen\n";
		return 0;
	};
	return launch_server &server;
};

Server^ -> u64
launch_server = \server:{
	Arena arena = arena_init (BUFFER_SIZE*2) ARENA_STATIC;
	u8^ buffer_region = (&arena) ## BUFFER_SIZE;
	[i8] buffer = [
		(buffer_region as i8^),
		BUFFER_SIZE
	];
	while 1 {
		print "Waiting for connection ...\n";
		u64 addrlen = sizeof sockaddr_in;
		sockaddr_in client_addr = {empty=0} as sockaddr_in;
		i32 new_socket =
			accept
				(server.socket)
				((&client_addr) as u8^)
				((&addrlen)     as socklen_t^);
		if new_socket < 0 {
			print "Error accepting connection\n";
		};
		u64 bytes_read =
			read
				new_socket
				(buffer.ptr as u8^)
				(buffer.len - 1);
		if bytes_read >= 0 {
			print buffer;
			print "\n";
		}
		else {
			print "Error reading buffer\n";
		};
		[i8] response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charser=UTF-8\r\n\r\n<!DOCTYPE html>\r\n<html><head>Hi from Ink</head></html>\r\n";
		write
			(new_socket as u64)
			(response.ptr as u8^)
			(response.len);
		close new_socket;
	};
	return 0;
};

u64 main = {
	return
		server_init
			AF_INET
			8080
			SOCK_STREAM
			0 10
			INADDR_ANY;
};
