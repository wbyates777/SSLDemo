/* SSLSocket 16/03/2015

    $$$$$$$$$$$$$$$$$$$$$
    $   SSLSocket.cpp   $
    $$$$$$$$$$$$$$$$$$$$$

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
#include "SSLSocket.h"
#endif


#include <iostream>

extern "C"
{
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h> 
}


//
// static variables, initialisation, and context registry stuff
//

int SSLSocket::m_initialised = SSLSocket::sslInitialiseLibrary();
std::map<std::string, SSL_CTX*> SSLSocket::m_contextFactory;

static void 
sigpipe_handle(int x);

static void 
sigpipe_handle(int x)
{
    std::cout << "sigpipe_handler called with " << x << std::endl;
}

// initialise the SSL library
// see https://www.openssl.org/docs/manmaster/man3/SSL_library_init
int 
SSLSocket::sslInitialiseLibrary( void )
{
    // set up a SIGPIPE handler
    ::signal(SIGPIPE, sigpipe_handle);
    ::SSL_load_error_strings();
    return ::SSL_library_init();
}

// register SSL contexts by their name
bool
SSLSocket::registerContext( SSLContext *context ) 
{ 
    std::map<std::string,SSL_CTX*>::const_iterator idx = m_contextFactory.find( context->getName() );
    SSL_CTX* ctx =  (idx != m_contextFactory.end()) ? idx->second : 0;
    
    if (ctx)
        SSL_CTX_free(ctx);
    
    ctx = sslContext(context);
    
    if (!ctx)
        return false;
    
    m_contextFactory.insert( std::map<std::string,SSL_CTX*>::value_type(context->getName(), ctx) );
    
    return true;
}

void
SSLSocket::clearRegister( void )
{
    for (std::map<std::string,SSL_CTX*>::iterator idx = m_contextFactory.begin(); idx != m_contextFactory.end(); ++idx)
        SSL_CTX_free(idx->second);
    
    m_contextFactory.clear();
}

//
//
//

SSLSocket::SSLSocket( const std::string& context ): Socket(), m_sslSocket(0), m_sslContext(0), m_sslSession(0), m_check(1) 
{
    std::map<std::string, SSL_CTX*>::const_iterator idx = m_contextFactory.find( context );
    m_sslContext =  (idx != m_contextFactory.end()) ? idx->second : 0;
    
    // allocate an SSL socket for the connection using this context
    m_sslSocket = SSL_new(m_sslContext);
    
    if (m_sslSocket == NULL)
    {
        ERR_print_errors_fp (stderr);
        exit(1);
    }
}

SSLSocket::~SSLSocket() 
{
    if (Socket::isOpen())
        Socket::close();
    
    if (m_sslSocket)
    {
        // see https://www.openssl.org/docs/manmaster/man3/SSL_shutdown
        if (SSL_shutdown (m_sslSocket) == 0)
            SSL_shutdown (m_sslSocket);
        
        // see https://www.openssl.org/docs/manmaster/man3/SSL_free
        SSL_free (m_sslSocket);
        m_sslSocket = 0;
    }
  
    // SSL_free clears the session but does not clear the context
    // but do not call SSL_CTX_free (m_sslContext);
    m_sslContext = 0;
    m_sslSession = 0;
    m_check = 0;
}

void
SSLSocket::setContext( const std::string& context ) 
{ 
    std::map<std::string,SSL_CTX*>::const_iterator idx = m_contextFactory.find( context );
    m_sslContext =  (idx != m_contextFactory.end()) ? idx->second : 0;
    
    if (m_sslSocket)
    {
        close();
        SSL_free(m_sslSocket);
        m_sslSocket = 0;
    }
    
    m_sslSocket = SSL_new(m_sslContext);
    
    if (m_sslSocket == NULL)
    {
        ERR_print_errors_fp (stderr);
        exit(1);
    }
    
    m_check = 1;
}

void 
SSLSocket::close(void) 
{    
    if (Socket::isOpen())
        Socket::close();
        
    if (m_sslSocket)
    {        
        // see https://www.openssl.org/docs/manmaster/man3/SSL_shutdown
        if (SSL_shutdown (m_sslSocket) == 0)
            SSL_shutdown (m_sslSocket);
  
        // see https://www.openssl.org/docs/manmaster/man3/SSL_clear
        if (SSL_clear(m_sslSocket) == 0)
            ERR_print_errors_fp(stderr);
    }
}

SSL_CTX*
SSLSocket::sslContext( SSLContext  *info )
{
    //
    // set the context for an SSL socket
    //
    
    if (!info)
    {
        std::cout << "Error SSL context not set" << std::endl;
        return 0;
    }
     
    //const SSL_METHOD* method = 0;
    //if (server)
    //    method = TLSv1_2_server_method();
    //else method = TLSv1_2_client_method();
    
    // create our context
    SSL_CTX *ctx = SSL_CTX_new( TLSv1_2_method() );
    
    if (ctx == NULL)
    {
        std::cout << "Could not allocate context" << std::endl;
        ERR_print_errors_fp (stderr);
        return 0;
    }
    
    // sets the SSL_VERIFY_PEER flag and the verify callback so certificate chain issuer and subject information can be printed. 
    // if you do not want to perform custom processing, then set the callback to NULL
    // see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_verify
    if (info->getVerifyPeer())
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback); // no diagnostics
    
    // load our keys and certificates
    // see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_use_certificate
    if (SSL_CTX_use_certificate_chain_file(ctx, info->getKeyfile().c_str()) != 1)
    {
        std::cout << "Could not read certificate file " << info->getKeyfile().c_str() << std::endl;
        ERR_print_errors_fp (stderr);
        SSL_CTX_free(ctx);
        return 0;
    }
    
    // set up a password call back function so that we can decrypt the private keyfile
    // these methods do not provide diagnostic information.
    // see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_default_passwd_cb
    SSL_CTX_set_default_passwd_cb(ctx, pem_password_cb);    
    SSL_CTX_set_default_passwd_cb_userdata( ctx, (void *) info->getPassword().c_str());
    
    // read the private key file
    // see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_use_certificate
    if (SSL_CTX_use_PrivateKey_file(ctx, info->getKeyfile().c_str(), SSL_FILETYPE_PEM) != 1)
    {
        ERR_print_errors_fp (stderr);
        std::cout << "Could not read key file" << std::endl;
        SSL_CTX_free(ctx);
        return 0;
    }
    
    // load the Certificate Authorities we trust; unencrypted as CA's are public domain
    // see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_load_verify_locations
    if (SSL_CTX_load_verify_locations(ctx, info->getCertificateList().c_str(), 0) != 1)
    {
        ERR_print_errors_fp (stderr);
        std::cout << "Could not read CA list" << std::endl;
        SSL_CTX_free(ctx);
        return 0;
    }
    
    // set up prefered ciphers; returns 1 if any cipher could be set; 0 if none
    // see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_cipher_list
    if (!info->getCipherList().empty())
    {
        if (!SSL_CTX_set_cipher_list(ctx, (char *) info->getCipherList().c_str() ))
        {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return 0;
        }
    }
    
    // use TLS protocol by disabling SSLv2 and SSLv3
    // see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_options
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags); // returns new bitmask
    
    if (info->getServer())
    {
        // only needed on server 
        
        // when DH enabled
        // see https://wiki.openssl.org/index.php/Diffie-Hellman_parameters
        if (info->getUseDH())
        {
            DH *params = setDHParams(info->DHFile());
            if (!params || SSL_CTX_set_tmp_dh(ctx, params) != 1)
            {
                std::cout << "Could not set DH parameters" << std::endl;
            }
            DH_free (params);
        }
                
        // for each session  created in this context we set its context id to getName()
        // this is needed if for example we plan to save sessions outside of cache 
        // see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_session_id_context
        SSL_CTX_set_session_id_context(ctx, (unsigned  char *) info->getName().c_str(), 5);
        SSL_CTX_set_timeout(ctx, 250);
        
        // see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_session_cache_mode
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    }
    
    //
    // end of context set up
    //
    
    return ctx;
}

bool 
SSLSocket::accept( SSLSocket& new_socket ) const 
{
    if (!Socket::accept(new_socket))
        return false;
    
    // if the new_socket has no context set one
    if (!new_socket.m_sslContext)
    {
        new_socket.m_sslContext = m_sslContext; 
        
        // allocate an SSL socket for the connection using this context
        new_socket.m_sslSocket = SSL_new(new_socket.m_sslContext);
        
        if (new_socket.m_sslSocket == NULL)
        {
            ERR_print_errors_fp (stderr);
            exit(1);
        }
    }
 
    // attatch the unencrypted connection m_socket to our SSL socket
    if (!SSL_set_fd(new_socket.m_sslSocket, new_socket.m_socket))
    {
        ERR_print_errors_fp (stderr); 
        exit(1);
    }
        
    // initiate SSL handshake
    if (SSL_accept(new_socket.m_sslSocket) == 1)
    {
        // see https://www.openssl.org/docs/manmaster/man3/SSL_session_reused
        //if (SSL_session_reused(new_socket.m_sslSocket) != 1)
        //    std::cout << "************* Server Session New" << std::endl;
        
        return true;
    }
    
    //ERR_print_errors_fp (stderr);
    
    return true;
}

bool
SSLSocket::connect( const std::string& IP, const int port )
{
    if (!Socket::connect(IP, port)) 
        return false;
    
    // attatch the unencrypted connection m_socket to our SSL socket
    if (!SSL_set_fd(m_sslSocket, m_socket))
    {
        ERR_print_errors_fp (stderr); 
        exit(1);
    }
    
    // initiate SSL handshake
    if (SSL_connect(m_sslSocket) == 1)
    {
        if (m_check)
            return certificateCheck( IP );
        
        return true;
    }
    
    //ERR_print_errors_fp (stderr);

    return false;
}

bool
SSLSocket::connect( const std::string& IP, const int port, const int seconds, const int microseconds )
{
    if ( !Socket::connect(IP, port, seconds, microseconds) ) 
        return false;
    
    // attatch the unencrypted connection m_socket to our SSL socket
    if (!SSL_set_fd(m_sslSocket, m_socket))
    {
        ERR_print_errors_fp (stderr); 
        exit(1);
    }
    
    // initiate SSL handshake
    if (SSL_connect(m_sslSocket) == 1)
    {
        if (m_check)
            return certificateCheck( IP );
        
        return true;
    }
    
    //ERR_print_errors_fp (stderr); 
        
    return false;
}

bool
SSLSocket::reconnect( void )
{
    if (!Socket::reconnect()) 
        return false;
    
    // attatch the unencrypted connection m_socket to our SSL socket
    // see https://www.openssl.org/docs/manmaster/man3/SSL_set_fd
    if (!SSL_set_fd(m_sslSocket, m_socket))
    {
        ERR_print_errors_fp (stderr); 
        exit(1);
    }
    
    // resume this session if possible returns 1 on success;
    // increments ref count on m_sslSession by one *if* it differs from one in context
    // see https://www.openssl.org/docs/manmaster/man3/SSL_set_session
    if (m_sslSession)
        SSL_set_session(m_sslSocket, m_sslSession);

    // initiate SSL handshakem 
    if (SSL_connect(m_sslSocket) == 1)
    {
        // see https://www.openssl.org/docs/manmaster/man3/SSL_session_reused
        //if (SSL_session_reused(m_sslSocket) != 1)
        //    std::cout << "************* Client Session New" << std::endl;
        
        // see https://www.openssl.org/docs/manmaster/man3/SSL_get_session
        SSL_SESSION *s = SSL_get1_session(m_sslSocket);
        
        if (s != m_sslSession)
        {
            SSL_SESSION_free(m_sslSession);
            m_sslSession = s;
        }
        
        return true;
    }
    
    ERR_print_errors_fp (stderr);
    
    return false;
}

bool
SSLSocket::reconnect( const int seconds, const int microseconds )
{
    if ( !Socket::reconnect(seconds, microseconds) ) 
        return false;

    // attatch the unencrypted connection m_socket to our SSL socket
    if (!SSL_set_fd(m_sslSocket, m_socket))
    {
        ERR_print_errors_fp (stderr); 
        exit(1);
    }
    
    // resume this session if possible returns 1 on success;
    // increments ref count on m_sslSession by one *if* it differs from one in context
    // see https://www.openssl.org/docs/manmaster/man3/SSL_set_session
    if (m_sslSession)
        SSL_set_session(m_sslSocket, m_sslSession);
    
    // initiate SSL handshakem 
    if (SSL_connect(m_sslSocket) == 1)
    {
        // see https://www.openssl.org/docs/manmaster/man3/SSL_session_reused
        //if (SSL_session_reused(m_sslSocket) != 1)
        //    std::cout << "************* Client Session New" << std::endl;
        
        // see https://www.openssl.org/docs/manmaster/man3/SSL_get_session
        SSL_SESSION *s = SSL_get1_session(m_sslSocket);
        
        if (s != m_sslSession)
        {
            SSL_SESSION_free(m_sslSession);
            m_sslSession = s;
        }
        
        return true;
    }

    //ERR_print_errors_fp (stderr); // this error crops up now and again; code still works
    
    return false;
}

//
// Data transmission methods; send, receive
//

bool 
SSLSocket::send( const std::vector<char>& msg ) const 
{
    if (!isOpen())
        return false;
    
    int nwritten = 0;
    const char* ptr = &msg[0];
    int nleft = msg.size(); 
    
    // write the size of the outgoing message in bytes as an int;
    if (::SSL_write(m_sslSocket, (char *) &nleft, sizeof(nleft)) < 0)
        return false;
    
    for ( ; nleft > 0; nleft -= nwritten, ptr += nwritten)
    {
        nwritten = ::SSL_write(m_sslSocket, ptr, nleft); // could improve error handling here
        if (nwritten < 0)
            return false;
    }
    
    return  true;    
}

bool 
SSLSocket::receive( std::vector<char>& msg )  const
// assumes sender closes connection thus sending EOF char
{
    if (!isOpen())
        return false;
    
    msg.clear();
    char buff[BUFFSIZE];
    bool isEOM = false; // is End Of Message?
    
    // read the size of the incomming message in bytes as an int
    // see https://www.openssl.org/docs/manmaster/man3/SSL_read
    int size = -1;
    int nread = 0;
    int tread = 0;
    int aread = 0;
    
    if (m_peek)
        nread = ::SSL_peek(m_sslSocket, (char*) &size, sizeof(size));
    else nread = ::SSL_read(m_sslSocket, (char*) &size, sizeof(size));
    
    if (nread != sizeof(size))
        return false;

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
                nread = ::SSL_peek(m_sslSocket, ptr, nleft);
            else nread = ::SSL_read(m_sslSocket, ptr, nleft);
            
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
SSLSocket::certificateCheck( const std::string& host ) const
// check that the common name on the certificate matches the host name
// see https://en.wikipedia.org/wiki/X.509
{  
    long errnum = 0;
    // see https://www.openssl.org/docs/manmaster/man3/SSL_get_verify_result
    if ((errnum = SSL_get_verify_result(m_sslSocket)) != X509_V_OK) // errnum = 1 is for uninitialized values
    {
        ERR_print_errors_fp(stderr);
        //std::cout << "Certificate does not verify " << errnum << std::endl;
        //exit(1);
    }
    
    // see https://www.openssl.org/docs/manmaster/man3/SSL_get_peer_certificate
    X509 *peer = SSL_get_peer_certificate( m_sslSocket );
    
    char peer_CN[256];
    
    X509_NAME_get_text_by_NID( X509_get_subject_name(peer), NID_commonName, peer_CN, 255 );
    
    if (strncasecmp(peer_CN, host.c_str(), 255))
    {
        std::cout << "Common name " << peer_CN << " does not match host name " << host << std::endl;
        return false;
    }
    
    return true;
}

// Below are is a Diffie-Hellman MODP group specified in RFC 3526, 
// More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE) 
// (the 1024-bit parameter is from RFC 2409). 
// They can be used with PEM_read_bio_DHparams and a memory BIO. 
// RFC 3526 also offers 1536-bit, 6144-bit and 8192-bit primes.

static const char g_dh4096_sz[] =
"-----BEGIN DH PARAMETERS-----\n"
"MIICCAKCAgEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb\n"
"IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft\n"
"awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT\n"
"mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh\n"
"fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq\n"
"5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM\n"
"fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq\n"
"ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI\n"
"ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O\n"
"+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI\n"
"HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8CAQI=\n"
"-----END DH PARAMETERS-----";


DH* 
SSLSocket::setDHParams( const std::string& dhFile )
// Diffie-Hellman parameters
// to use perfect forward secrecy cipher suites, you must set up Diffie-Hellman parameters (on the server side)
// you can generate random Diffie-Hellman parameters with the dhparam command line program with the -C option 
// and embed the resulting code fragment in your program (see above)
// see https://wiki.openssl.org/index.php/Diffie-Hellman_parameters
{
    BIO *bio;
    
    if (dhFile.size())
    {
        if ((bio = BIO_new_file(dhFile.c_str(),"r")) == NULL)
            std::cout << "Could not open DH file " << dhFile << std::endl;
    }
    else if ((bio = BIO_new_mem_buf( (void*) g_dh4096_sz, sizeof(g_dh4096_sz) )) == NULL)
    {
        std::cout << "Error reading in memory DH" << std::endl;
        return 0;
    }
    
    DH *params = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    
    BIO_free(bio);
    
    int codes = 0;
    if (DH_check(params, &codes) != 1)
    {
        std::cout << "Could not validate DH parameters" << std::endl;
        
        if (codes & DH_UNABLE_TO_CHECK_GENERATOR)
            std::cout << "DH_check: failed to test generator" << std::endl;
        
        if (codes & DH_NOT_SUITABLE_GENERATOR)
            std::cout << "DH_check: g is not a suitable generator" << std::endl;
        
        if (codes & DH_CHECK_P_NOT_PRIME)
            std::cout << "DH_check: p is not prime" << std::endl;
        
        if (codes & DH_CHECK_P_NOT_SAFE_PRIME)
            std::cout << "DH_check: p is not a safe prime" << std::endl;
        
        return 0;
    }
       
    return params;
}


int 
SSLSocket::pem_password_cb( char *buf, int buf_size, int rwflag, void *userdata )
// copy password into buffer which has size buf_size
// rwflag = 0 read/decrypt, rwflag = 1 write/encrypt
// return password length
{
    char* passw = (char*) userdata;
    
    int len = std::strlen(passw);
    
    if (buf_size < len + 1)
        return 0;
    
    std::strncpy(buf, passw, len); 
    
    return len;
}


//
// Simple, example verify_callback
//

int 
SSLSocket::verify_callback(int ok, X509_STORE_CTX *ctx)
{
    X509 *err_cert = X509_STORE_CTX_get_current_cert(ctx);
    int  err =	X509_STORE_CTX_get_error(ctx);
    
    // if testing with your own self signed certificates uncomment this
    if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) // self signed certificate
        return 1;
    
    int depth =	X509_STORE_CTX_get_error_depth(ctx);
    
    BIO *bio_err = BIO_new_fp(stderr, 'w');
    BIO_printf(bio_err,"depth=%d ",depth);
    
    if (err_cert)
    {
        X509_NAME_print_ex(bio_err, X509_get_subject_name(err_cert), 0, XN_FLAG_ONELINE);
        BIO_puts(bio_err, "\n");
    }
    else
    {
        BIO_puts(bio_err, "<no cert>\n");
    }
    
    if (!ok)
        BIO_printf(bio_err,"verify error:num=%d:%s\n",err, X509_verify_cert_error_string(err));
    
    switch (err)
    {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            BIO_puts(bio_err,"issuer= ");
            X509_NAME_print_ex(bio_err, X509_get_issuer_name(err_cert), 0, XN_FLAG_ONELINE);
            BIO_puts(bio_err, "\n");
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            BIO_printf(bio_err,"notBefore=");
            ASN1_TIME_print(bio_err,X509_get_notBefore(err_cert));
            BIO_printf(bio_err,"\n");
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            BIO_printf(bio_err,"notAfter=");
            ASN1_TIME_print(bio_err,X509_get_notAfter(err_cert));
            BIO_printf(bio_err,"\n");
            break;
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            //policies_print(bio_err, ctx);
            break;
    }
    
    // print out policies 
    if (err == X509_V_OK && ok == 2)
        BIO_printf(bio_err,"verify return:%d\n",ok);

    return ok;
}


//









