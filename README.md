## First SRSC Project README

### Run Instructions to connect to the mchat:

    java -jar Cliente.jar <username> <multicast_address> <port> <userpw>
    
    where:
    	* <username> - The username of the client
    	* <multicast_address> -  The multicast addresses are in the range 224.0.0.0 through 239.255.255.255
	* <port> - The multicast port number 
    	* <userpw> - The user password
	
    Example:
        java -jar Cliente.jar maria 224.10.10.10 1800 benfica

### Run Instructions to run the server:	
	java -jar Server.jar <keystorepw> <keypw>
    where:
	* <keystorepw> - The password to create or to acess the keystore already created
	* <keypw> - The password to create or to acess all key entries

    Example:	
	java -jar Server.jar projeto srsc1718

#### Authors:

	* André Lopes nº 45617
	* Nelson Coquenim nº 45694
	* Simão Dolores nº 45020
