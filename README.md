## First SRSC Project README

### Run Instructions:

    java -cp <classpath> <main class> <username> <multicast_address> <port>
    
    where:
    	* <classpath> - the list of directories and/or JAR-files where needed classes reside separated by ";" for Windows or ":" for linux
    	* <main class> - fully qualified name of the class containig main() method
    	* <multicast_address> -  The multicast addresses are in the range 224.0.0.0 through 239.255.255.255
    	
    Example:
        java -cp ./bin MCHAT.MChatCliente myAwesomeNickname 224.30.80.9 10000



#### Authors:

	* André Lopes nº 45617
	* Nelson Coquenim nº 45694
	* Simão Dolores nº 45020