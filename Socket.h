/* Socket 02/09/09

    $$$$$$$$$$$$$$$$$$$$$$$$$
    $   Socket.h - header   $
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

#ifndef __SOCKET_H__
#define __SOCKET_H__


#include <string>
#include <vector>


extern "C"
{
#ifndef _ARPA_INET_H_
#include <arpa/inet.h> 
#endif
}


class Persistent;

class Socket
{
public:
	Socket( void );
	virtual ~Socket( void );

    bool 
    isOpen( void ) const { return m_socket != -1; }
    
    std::string 
    getAddress( void ) const { return ::inet_ntoa(m_addr.sin_addr); }
    
    unsigned short 
    getPort( void ) const { return ntohs(m_addr.sin_port); }
    
    unsigned long 
    getIP( void ) const { return ntohl(m_addr.sin_addr.s_addr); }
    
    //
	virtual bool
	open( void );

	virtual void
	close( void );

	// server methods
	bool 
	bind( const int port );
	
	bool 
	listen( void ) const;
	
	virtual bool 
	accept( Socket& from ) const;

	// client methods
	virtual bool 
	connect( const std::string& IP, const int port );

    //  timeout after seconds, microseconds - 1000000 microseconds equals 1 second
    virtual bool
    connect( const std::string& IP, const int port, const int seconds, const int microseconds = 0 ); 
    
    // after close() reconnect to same server
    virtual bool 
    reconnect( void );
    
    virtual bool
    reconnect( const int seconds, const int microseconds = 0 );
    
    //
	// data transimission
	//
    virtual bool 
    send( const std::vector<char>& msg ) const; 
    
    virtual bool 
    receive( std::vector<char>& msg ) const;
    
	bool 
	send( const std::string& msg ) const;

	bool 
	receive( std::string& msg ) const;

    //
    // socket configuration
    //
	bool 
	setNonBlocking( const bool );
    
    // set time out for send and recieve - 1000000 microseconds equals 1 second
    bool 
    setSendTimeout( const int seconds, const int microseconds = 0 );
    
    bool 
    setRecvTimeout( const int seconds, const int microseconds = 0 );

	void 
	setPeek(const int setting) { m_peek = setting; }

    //
    // static stuff
    //
    static std::string 
	getHostIPAddress( const std::string& host );
	
	static std::string 
	getLocalIPAddress( void );

    
    //
    // general socket configuration
    //
    static int
    getBufferSize( void ) { return BUFFSIZE; }
    
    static void
    setBufferSize( int bs ) { BUFFSIZE = bs; }
 
    static int
    getMaxConnections( void ) { return MAXCONNECTIONS; }
    
    static void
    setMaxConnections( int mc ) { MAXCONNECTIONS = mc; }
    
protected:
    
    // copy/assignment disabled
    Socket( const Socket& )=delete;
    
    Socket&
    operator=( const Socket& )=delete;
    //
    
	int    m_socket;
	int	   m_peek;
	struct sockaddr_in m_addr;
    
    static int MAXCONNECTIONS;
    static int BUFFSIZE;
    
};
  
  
#endif


