/* SSLDemo 16/03/2015
 
    $$$$$$$$$$$$$$$$$$$
    $   SSLDemo.cpp   $
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


#include <iostream>
#include <thread>
#include <unistd.h>

#ifndef __SSLSOCKET_H__
#include "SSLSocket.h"
#endif

const int PORT = 4123;

void
sender1( SSLSocket *client ) 
{
    int count = 3;
    if (client->open()) // 127.0.0.1
    {
        std::cout << "client1 connecting"  << std::endl;
        if (client->connect("127.0.0.1", PORT))
        {
            while (count--)
            {
                std::cout << "   client1 sending 'Hello World'" << std::endl;
                client->send(std::string("Hello World"));
                std::string msg;
                if (client->receive(msg))
                    std::cout << "    client1 receiving " << msg << std::endl;
                sleep(1);
            }
        }
    }
    client->close(); // close sends the EOF that allows receiver to read the message        
    std::cout << "client1 closed" << std::endl;
}

void
sender2( SSLSocket *client ) 
{
    int count = 3;
    std::cout << "client2 re-connecting"  << std::endl;
    if (client->open() && client->reconnect())
    {
        while (count--)
        {
            std::cout << "   client2 sending 'Hello World'" << std::endl;
            client->send(std::string("Hello World"));
            std::string msg;
            if (client->receive(msg))
                std::cout << "   client2 receiving " << msg << std::endl;
            sleep(1);
        }
    }
    client->close(); // close sends the EOF that allows receiver to read the message        
    std::cout << "client2 closed" << std::endl;
}

void
rec( SSLSocket *server ) 
{   
    server->open();
    server->bind(PORT);
    server->listen();
    
    int count = 3;
    
    SSLSocket client;
    
    // Socket client;
    // we block here
    if ( server->accept(client) )
    {
        while (count--)
        {
            std::string msgIn;
            if ( client.receive(msgIn) )
            {
                std::cout << "Server recieved message: '" << msgIn << "'" << std::endl;
                std::cout << "Server sending ACK" << std::endl;
                client.send("ACK");
            }
            sleep(1);
        }
    }
    server->close();
    std::cout << "Server closed" << std::endl;      
}


int
main(int argc, char *argv[])
{  
    std::cout << "\nSSLDemo  Copyright (C) 2023,  W. B. Yates" << std::endl;
    std::cout << "\nThis program comes with ABSOLUTELY NO WARRANTY;" << std::endl;
    std::cout << "for details see http://www.gnu.org/licenses/." << std::endl;
    std::cout << "This is free software, and you are welcome to redistribute it" << std::endl;
    std::cout << "under certain conditions; see http://www.gnu.org/licenses/\n" << std::endl;
    
    //               name,     keyfile,      PEM pass phrase
    SSLContext ctx1("client", "client.pem", "password");
    SSLContext ctx2("server", "server.pem", "password", true);
    
    SSLSocket::registerContext( &ctx1 );
    SSLSocket::registerContext( &ctx2 );
    
    SSLSocket client;
    client.setContext("client");
    
    SSLSocket server("server");
    
    //Socket client;
    //Socket server;
    

    for (int i = 0; i < 5; ++i)
    {
        std::cout << "\nBegin socket test " << i + 1 <<  std::endl;
        std::thread thread1 = std::thread(rec, &server);
        std::thread thread2;
        
        if (i == 0)
            thread2 = std::thread(sender1, &client);
        else thread2 = std::thread(sender2, &client);
        
        thread1.join();
        thread2.join();
    }

    
    std::cout << "End socket test" <<  std::endl;
    SSLSocket::clearRegister();
}
