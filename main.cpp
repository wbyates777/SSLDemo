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
    The implementation of OpenSSL used here is LibreSSL 2.3.0 released September 23, 2015, see http://www.libressl.org
    We support session resumption on server and client sides

    See also: 

    https://en.wikipedia.org/wiki/X.509 

    https://en.wikipedia.org/wiki/Transport_Layer_Security

    Compile with the library flags:  -lssl -lcrypto
 
*/


#include <iostream>
#include <thread>

#ifndef __SSLSOCKET_H__
#include "SSLSocket.h"
#endif

void
sender1( SSLSocket *client ) 
{
    int count = 3;
    if (client->open() && client->connect("localhost", 5000))
    {
        while (count--)
        {
            client->send(std::string("Hello World"));
            std::string ACK;
            if (client->receive(ACK))
                std::cout << "client receiving " << ACK << std::endl;;
            sleep(1);
        }
    }
    client->close(); // close sends the EOF that allows receiver to read the message        
    std::cout << "Client closed" << std::endl;
}

void
sender2( SSLSocket *client ) 
{
    int count = 3;
    if (client->open() && client->reconnect())
    {
        while (count--)
        {
            client->send(std::string("Hello World"));
            std::string ACK;
            if (client->receive(ACK))
                std::cout << "  client receiving " << ACK << std::endl;;
            sleep(1);
        }
    }
    client->close(); // close sends the EOF that allows receiver to read the message        
    std::cout << "Client closed" << std::endl;
}

void
rec( SSLSocket *server ) 
{   
    server->open();
    server->bind( 5000 );
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
                std::cout << "Server recieved message: " << msgIn << std::endl;
                std::cout << "Server sending ACK" << std::endl;
                std::string rep("ACK");
                client.send(rep);
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
    std::cout << "SSLDemo  Copyright (C) 2015,  W. B. Yates" << std::endl;
    std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details see http://www.gnu.org/licenses/." << std::endl;
    std::cout << "This is free software, and you are welcome to redistribute it" << std::endl;
    std::cout << "under certain conditions; see http://www.gnu.org/licenses/" << std::endl;
    
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
        std::thread thread1 = std::thread(rec,&server);
        std::thread thread2;
        
        if (i == 0)
            thread2 = std::thread(sender1,&client);
        else thread2 = std::thread(sender2,&client);
        thread1.join();
        thread2.join();
    }

    
    std::cout << "End socket test" <<  std::endl;
}
