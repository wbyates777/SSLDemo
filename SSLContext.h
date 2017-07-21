/* SSLContext 18/03/2015

    $$$$$$$$$$$$$$$$$$$$
    $   SSLContext.h   $
    $$$$$$$$$$$$$$$$$$$$

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

    For more information on setting list of prefered ciphers see

    http://wiki.openssl.org/index.php/SSL/TLS_Client

    and 

    http://wiki.openssl.org/index.php/Manual:Ciphers(1)
 
*/


#ifndef __SSLCONTEXT_H__
#define __SSLCONTEXT_H__

#include <string>

class SSLContext
{
    
public:
    
    SSLContext( void ) : m_server(0),
                         m_certificateCheck(0),
                         m_verifyPeer(1),
                         m_useDH(1),
                         m_name("client"),
                         m_cipherList("HIGH:!aNULL:!NULL:eNULL:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS"), 
                         m_certificateList("root.crt"), 
                         m_keyfile(),
                         m_password(),
                         m_dhFile("dh1024.pem") {}
    
    SSLContext( const std::string& name, const std::string& keyfile, const std::string& password, bool server = false )
                        : m_server(server),
                          m_certificateCheck(0),
                          m_verifyPeer(1),
                          m_useDH(1),
                          m_name(name),
                          m_cipherList("HIGH:!aNULL::!NULL:eNULL!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS"), 
                          m_certificateList("root.crt"), 
                          m_keyfile(keyfile),
                          m_password(password),
                          m_dhFile("dh1024.pem") {}
    
    
    const std::string& 
    getName( void ) const { return m_name; }
    
    void 
    DHFile( const std::string& n ) { m_dhFile = n; }
    
    const std::string& 
    DHFile( void ) const { return m_dhFile; }
    
    void 
    setName( const std::string& n ) { m_name = n; }
    
    void 
    setKeyDetails( const std::string& keyfile, const std::string& password )
    {
        m_keyfile = keyfile;
        m_password = password;
    }
    
    const std::string& 
    getPassword( void ) const { return m_password; }
    
    const std::string& 
    getKeyfile( void ) const { return m_keyfile; }
    
    void 
    setServer( const bool b ) { m_server = b; }
    
    bool
    getServer( void ) const { return m_server; }
    
    void 
    setCipherList( const std::string& cl ) { m_cipherList = cl; }
    
    const std::string& 
    getCipherList( void ) const { return m_cipherList; }
    
    // set/get the default locations for trusted CA certificates
    void 
    setCertificateList( const std::string& cl ) { m_certificateList = cl; }
    
    const std::string& 
    getCertificateList( void ) const { return m_certificateList; }
    
    // check certificates on connect
    void 
    setCertificateCheck( const bool b ) { m_certificateCheck = b; }
    
    bool
    getCertificateCheck( void ) const { return m_certificateCheck; }
    
    void 
    setVerifyPeer( const bool b ) { m_verifyPeer = b; }
    
    bool
    getVerifyPeer( void ) const { return m_verifyPeer; }
    
    // use Diffie-Hellman parameters for perfect forward secrecy cipher suites
    // see https://wiki.openssl.org/index.php/Diffie-Hellman_parameters
    void 
    setUseDH( const bool b ) { m_useDH = b; }
    
    bool
    getUseDH( void ) const { return m_useDH; }
    
private:
    
    int             m_server;
    int             m_certificateCheck;
    int             m_verifyPeer;
    int             m_useDH;
    std::string     m_name;
    std::string     m_cipherList;
    std::string     m_certificateList;
    std::string     m_keyfile;
    std::string     m_password;
    std::string     m_dhFile;
};



#endif


