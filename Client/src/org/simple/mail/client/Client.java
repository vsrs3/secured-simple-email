package org.simple.mail.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.simple.mail.util.Request;


public class Client {
	private static final String SERVER_ADDR = "127.0.0.1";
	private static final int SERVER_PORT = 5000;
	public static void main(String[] args) {
		InetAddress servAddr;
		try {
			servAddr = InetAddress.getByName(SERVER_ADDR);
			try(Socket clientSocket = new Socket(servAddr, SERVER_PORT);
				BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
			){
						UserProcessor processor = new UserProcessor(clientSocket);
						String buffer;
						while(true){
							System.out.print("Send: ");
							buffer = user.readLine();
							
							Request request = new Request(buffer);			
							processor.setRequest(request);
							if(processor.process()< 0) break;							
						}	
						
					}catch (IOException e){
						e.printStackTrace();
					}
		} catch (UnknownHostException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		System.out.println("QUIT!!!");
	}
}