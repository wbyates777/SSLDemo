/* Socket 02/09/09

    $$$$$$$$$$$$$$$$$$$$$$$$$
    $   Socket.cpp - code   $
    $$$$$$$$$$$$$$$$$$$$$$$$$


    History: Very simple socket class 

    Copyright (C) 2009  W.B. Yates

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see http://www.gnu.org/licenses/
 
*/

#include <iostream>

#ifndef __SOCKET_H__
#include "Socket.h"
#endif

extern "C"
{
#include <sys/types.h>    
#include <sys/socket.h>    
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
}

//
// default values
//
int Socket::MAXCONNECTIONS  =  64; // 128;
int Socket::BUFFSIZE = 1024;  // 8192

std::string 
Socket::getLocalIPAddress( void ) 
{
	char host[255];
    
    char IP[40];	
	std::strncpy(IP, "0.0.0.0", 7);
    
    gethostname(host, 254);
    hostent *hostEntry = gethostbyname2(host, AF_INET);
    
    if (hostEntry)
	{
		char *hostAddress = hostEntry->h_addr_list[0];
		
	
		sprintf(IP, "%u.%u.%u.%u",	*((unsigned char *) &hostAddress[0]), 
									*((unsigned char *) &hostAddress[1]),
									*((unsigned char *) &hostAddress[2]),
									*((unsigned char *) &hostAddress[3]));
	}
	return IP;
}

std::string 
Socket::getHostIPAddress( const std::string& host ) 
{
	char IP[40];
	std::strncpy(IP, "0.0.0.0", 7);
	
    hostent *hostEntry = gethostbyname2(host.c_str(), AF_INET);
	
    if (hostEntry)
	{
		char *hostAddress = hostEntry->h_addr_list[0];
		
	
		sprintf(IP, "%u.%u.%u.%u", *((unsigned char *) &hostAddress[0]), 
                                   *((unsigned char *) &hostAddress[1]),
								   *((unsigned char *) &hostAddress[2]),
								   *((unsigned char *) &hostAddress[3]));	
	}
	return IP;
}



Socket::Socket( void ): m_socket(-1), m_peek(0), m_addr()
{
	std::memset( &m_addr, 0, sizeof( m_addr ) );
}

Socket::~Socket( void )
{
    if ( isOpen() )
        ::close( m_socket );

    std::memset( &m_addr, 0, sizeof( m_addr ) );
    m_socket = -1;
    m_peek = 0;
}

bool 
Socket::open( void )
{
	if (isOpen())
		return true;
	
    m_socket = ::socket( AF_INET, SOCK_STREAM, 0 );  
	
    if ( !isOpen() )
		return false;

    // set to 1 to enable, 0 to disable
	int on = 1;   
	if ( ::setsockopt( m_socket, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, sizeof( on )) == -1 )
		return false;

	if ( ::setsockopt( m_socket, SOL_SOCKET, SO_KEEPALIVE, (const char*) &on, sizeof( on )) == -1 )
		return false;
    
	return true;
}

void 
Socket::close( void )
{
	if ( isOpen() )
		::close( m_socket );
    m_socket = -1;
    m_peek = 0;
}

bool
Socket::bind( const int port )
{
    if (!isOpen())
        return false;

    m_addr.sin_family = AF_INET; 
	m_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	m_addr.sin_port = htons( port );

	if ( ::bind(m_socket, (struct sockaddr *) &m_addr, sizeof(m_addr)) == -1 )
		return false;

	return true;
}

bool
Socket::listen( void ) const
{
    if (!isOpen())
        return false;

	if ( ::listen(m_socket, MAXCONNECTIONS) == -1)
		return false;

	return true;
}

bool 
Socket::accept( Socket& new_socket ) const
{
    if (!isOpen())
        return false;
    
	int addr_length = sizeof(m_addr);
	new_socket.m_socket = ::accept( m_socket, (sockaddr *) &m_addr, (socklen_t *) &addr_length );

	if ( new_socket.m_socket <= 0 )
		return false;
	
    return true;
}

bool
Socket::connect( const std::string& IP, const int port )
{
	if ( !isOpen() ) 
		return false;
	
	m_addr.sin_family = AF_INET;
	m_addr.sin_port = htons( port );
	
    // return 1 if ok, 0 if IP could not be parsed and -1 for error and errno set
    ::inet_pton( AF_INET, IP.c_str(), &m_addr.sin_addr );
	
	if ( errno == EAFNOSUPPORT ) 
		return false;

	if ( ::connect(m_socket, (sockaddr *) &m_addr, sizeof(m_addr)) == 0 )
		return true;
	
	return false;
}

bool
Socket::connect( const std::string& IP, const int port, const int seconds, const int microseconds )
{
    if ( !isOpen() ) 
        return false;
    
    setNonBlocking(true);

    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons( port );
    
    // return 1 if ok, 0 id could not parse and -1 for error and errno set
    ::inet_pton(AF_INET, IP.c_str(), &m_addr.sin_addr);
    
    if ( errno == EAFNOSUPPORT ) 
        return false;
    
    bool retVal = true;
    
    // attempt a non-blocking connect
    // on error, -1 is returned, and errno is set appropriately;
    if (::connect(m_socket, (sockaddr *) &m_addr, sizeof(m_addr)) < 0) 
    { 
        retVal = false;
        if (errno == EINPROGRESS) 
        { 
            fd_set myset;
            FD_ZERO(&myset); // initialise file descriptor set
            FD_SET(m_socket, &myset); // set file descriptor set
            
            struct timeval tv;
            tv.tv_sec = seconds; 
            tv.tv_usec = microseconds; 
            
            // int select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
            if (::select(m_socket + 1, NULL, &myset, NULL, &tv) > 0) 
            { 
                int errNum;
                socklen_t lon = sizeof(errNum); 
                
                // int getsockopt(int socket, int level, int optname, void *optval, socklen_t *optlen);
                if ((::getsockopt(m_socket, SOL_SOCKET, SO_ERROR, (void*)(&errNum), &lon) == 0) && (errNum == 0)) 
                    retVal = true;
            } 
        } 
    } 

    setNonBlocking(false);
    
    return retVal;
}

bool
Socket::reconnect( void )
{
    return (isOpen()) ? (::connect(m_socket, (sockaddr *) &m_addr, sizeof(m_addr)) == 0) : false;
}

bool
Socket::reconnect( const int seconds, const int microseconds )
{
    if ( !isOpen() ) 
        return false;
    
    setNonBlocking(true);
    
    bool retVal = true;
    
    // attempt a non-blocking connect
    // on error, -1 is returned, and errno is set appropriately;
    if (::connect(m_socket, (sockaddr *) &m_addr, sizeof(m_addr)) < 0) 
    { 
        retVal = false;
        if (errno == EINPROGRESS) 
        { 
            fd_set myset;
            FD_ZERO(&myset); // initialise file descriptor set
            FD_SET(m_socket, &myset); // set file descriptor set
            
            struct timeval tv;
            tv.tv_sec = seconds; 
            tv.tv_usec = microseconds;  
            
            // int select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
            if (::select(m_socket + 1, NULL, &myset, NULL, &tv) > 0) 
            { 
                int errNum;
                socklen_t lon = sizeof(errNum); 
                
                // int getsockopt(int socket, int level, int optname, void *optval, socklen_t *optlen);
                if ((::getsockopt(m_socket, SOL_SOCKET, SO_ERROR, (void*)(&errNum), &lon) == 0) && (errNum == 0)) 
                    retVal = true;
            } 
        } 
    } 
    
    setNonBlocking(false);
    
    return retVal;
}

//
// Data transmission methods; send, receive
//

bool 
Socket::send( const std::vector<char>& msg ) const 
{
	if (!isOpen())
		return false;

	ssize_t nwritten = 0;
	const char* ptr = &msg[0];
	unsigned long nleft = msg.size(); 
    
    // write the size of the outgoing message in bytes as an int;
    if (::write(m_socket, (char *) &nleft, sizeof(nleft)) < 0)
        return false;
    
	for ( ; nleft > 0; nleft -= nwritten, ptr += nwritten)
	{
		nwritten = ::write(m_socket, ptr, nleft);
		if (nwritten < 0)
			return false;
	}
	return  true;
	
}

bool 
Socket::receive( std::vector<char>& msg )  const
// assumes sender closes connection thus sending EOF char
{
    if (!isOpen())
        return false;

    msg.clear();
	char buff[BUFFSIZE];
	bool isEOM = false; // is End Of Message?
    
    // read the size of the incomming message in bytes as an int
    int size = -1;
    ssize_t nread = 0;
    int tread = 0;
    int aread = 0;
    
    if (m_peek)
        nread = ::recv(m_socket, (char*) &size, sizeof(size), MSG_PEEK);
    else nread = ::read(m_socket, (char*) &size, sizeof(size));
    
    if (nread != sizeof(size))
        return false;
    
    // add the size of the initial integer that has already been read - this fix was added 10/02/22
    size += 4;
	
    while (!isEOM)
    {
        ::memset( buff, 0, BUFFSIZE );
	int nleft = BUFFSIZE;
        nread = 0;
        tread = 0;
	char* ptr = buff;
        
	for ( ; !isEOM && nleft > 0; nleft -= nread, ptr += nread )
	{
	    if (m_peek)
		nread = ::recv(m_socket, ptr, nleft, MSG_PEEK);
	    else nread = ::read(m_socket, ptr, nleft);

            if (nread < 0)
                return false;
            
            // nread == 0 indicates an EOF (the sender has closed their connection)
            // (nread + tread) == size indicates that 'this' message has been read
            if ( nread == 0 || (nread + aread) == size )
                isEOM = true;
            
            tread += nread;
            aread += nread;
	}
        
		msg.insert(msg.end(), buff, buff + tread);
    }
	
    return (aread == size); 
}

bool 
Socket::send( const std::string& msg ) const
{
    return send( std::vector<char>(msg.begin(),msg.end()) ); 
}

bool 
Socket::receive( std::string& msg ) const
{
    std::vector<char> val; 
    
    bool ok = receive( val );
    
    msg.clear();
    msg.insert(msg.end(), val.begin(), val.end());
    
    return ok;
}

bool 
Socket::setSendTimeout( const int seconds, const int microseconds )
{
    timeval tval;
    tval.tv_sec = seconds;                  
    tval.tv_usec = microseconds;            
    
    if ( ::setsockopt( m_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*) &tval, sizeof( tval )) == -1 )
        return false;
    
    return true;
}

bool 
Socket::setRecvTimeout( const int seconds, const int microseconds)
{
    timeval tval;
    tval.tv_sec = seconds;               
    tval.tv_usec = microseconds;     
    
    if ( ::setsockopt( m_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tval, sizeof( tval )) == -1 )
        return false;
    
    return true;
}

bool 
Socket::setNonBlocking( const bool b )
{
	int opts = ::fcntl( m_socket, F_GETFL );

	if ( opts < 0 )
		return false;

	if ( b )
		opts = ( opts | O_NONBLOCK );
	else opts = ( opts & ~O_NONBLOCK );

	return ::fcntl( m_socket, F_SETFL, opts ) < 1;
}



