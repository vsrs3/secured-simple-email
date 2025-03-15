package org.simple.mail.server;

import java.io.IOException;
import java.net.ServerSocket;

public class Server {
	private final static int PORT = 5000;
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try(ServerSocket servSocket = new ServerSocket(PORT);
		){
			while(true){
				Runnable t = new ServerWorker(servSocket.accept());
				new Thread(t).start();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
