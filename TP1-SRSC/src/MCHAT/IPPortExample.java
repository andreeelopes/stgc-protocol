package MCHAT;

import java.io.*;
import java.net.*;
import java.util.*;

public class IPPortExample
{ 
  public static void main( String args[]) throws Exception {
	  IPPort ipport = IPPort.generateWellKnown();
	  System.out.println( "IP = " + ipport.ip + " ; port = " + ipport.port);

	  BufferedReader reader = new BufferedReader( new InputStreamReader( System.in));
	  for( ; ; ) {
		  ipport = IPPort.generateNew();
		  System.out.println( "IP = " + ipport.ip + " ; port = " + ipport.port);
		  
		  
		  System.out.print( "0 para sair >");
		  System.out.flush();
		  if( reader.readLine().equals( "0"))
			  break;
	  }
  }
}

