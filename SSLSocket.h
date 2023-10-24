/* SSLSocket 16/03/2015 - Secure Socket Layer Socket

    $$$$$$$$$$$$$$$$$$$
    $   SSLSocket.h   $
    $$$$$$$$$$$$$$$$$$$

    Copyright (C) 2015  W.B. Yates

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


     History:   

     Very simple secure socket class
     We use the OpenSSL interface, see https://wiki.openssl.org/index.php/Main_Page  
     and the TLS protocol, see https://tools.ietf.org/html/rfc5246 
     We support session resumption on server and client sides
     
     *** Updated 24/10/23 ***

     The implementation of OpenSSL used here is OpenSSL 3.1.3 19 Sep 2023
     We recommend LibreSSL see https://www.libressl.org

     See also: 

     https://en.wikipedia.org/wiki/X.509 

     https://en.wikipedia.org/wiki/Transport_Layer_Security

     Compile with the library flags:  -lssl -lcrypto
                    
*/

#ifndef __SSLSOCKET_H__
#define __SSLSOCKET_H__

#ifndef __SOCKET_H__
#include "Socket.h"
#endif

#ifndef __SSLCONTEXT_H__
#include "SSLContext.h"
#endif

#include <map>

extern "C"
{
#ifndef HEADER_SSL_H
#include <openssl/ssl.h>
#endif
}

class SSLSocket : public Socket
{
public:
    
    SSLSocket( void ): Socket(), m_sslSocket(0), m_sslContext(0), m_sslSession(0), m_check(1) {}
    
    SSLSocket( const std::string& context );
    
    virtual ~SSLSocket( void );
    
    virtual void
    close( void );
    
    // you must set a context before calls to accept or calls to connect
    // usually (though not always) set once for the sockets lifetime
    void
    setContext( const std::string& context ); 
    
    virtual bool 
    accept( SSLSocket& client ) const;

    virtual bool 
    connect( const std::string& IP, const int port );
    
    // timeout after seconds, microseconds - 1000000 microseconds equals 1 second
    virtual bool
    connect( const std::string& IP, const int port, const int seconds, const int microseconds = 0 ); 
    
    // after close() reconnect to same server; resume session if possible
    virtual bool 
    reconnect( void ); 
    
    virtual bool
    reconnect( const int seconds, const int microseconds = 0 ); 
    
    // data transimission
    // text and persistent data defined in Socket.h
    using Socket::send;
    using Socket::receive;
    
    // binary data
    virtual bool 
    send( const std::vector<char>& msg ) const; 
    
    virtual bool 
    receive( std::vector<char>& msg ) const;
    // end of data transmission
      
    
    //
    // static stuff
    //
    
    static bool
    initialised( void ) { return m_initialised; }    
  
    // register context(s) before creating any sockets
    // will overwite any existing context if contexts have same name
    static bool
    registerContext( SSLContext *context );
    
    static void
    clearRegister( void );
    
protected:
    
    // super class accept disabled
    virtual bool 
    accept( Socket& client ) const { return true; }
    
    // copy/assignment disabled
    SSLSocket( const SSLSocket& )=delete;
    
    SSLSocket&
    operator=( const SSLSocket& )=delete;
    //
    
    bool 
    certificateCheck( const std::string& host ) const;
    
    SSL         *m_sslSocket;
    SSL_CTX     *m_sslContext;
    SSL_SESSION *m_sslSession;
    int          m_check;
 
    //
    // statics
    //
    
    static void 
    print_cn_name(const char* label, X509_NAME* const name);
    
    static void 
    print_san_name(const char* label, X509* const cert);
    
    static int 
    verify_callback(int preverify, X509_STORE_CTX* x509_ctx);
    
    static int 
    pem_password_cb(char *buf, int num, int rwflag, void *userdata);
    
    static SSL_CTX*
    sslContext( SSLContext *info );
    
    static DH* 
    setDHParams( const std::string& dhFile );
    
    static int 
    sslInitialiseLibrary( void );
    
    static int m_initialised;
    static std::map<std::string, SSL_CTX*>  m_contextFactory;
};

#endif

//


