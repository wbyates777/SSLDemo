
# SSLDemo
A C++ program that demonstrates the use of the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols 

By default (for safety) the code verifies certificates and will *REJECT* self signed certificates.
If you are testing this code with the bundled self signed certificates you must uncomment the lines

	// if testing with your own self signed certificates uncomment this
	// if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) // self signed certificate
	//    return 1;

in the method

	int SSLSocket::verify_callback(int ok, X509_STORE_CTX *ctx)

in the file SSLSocket.cpp. Otherwise the demo will *NOT* work


WBY 10/02/22
