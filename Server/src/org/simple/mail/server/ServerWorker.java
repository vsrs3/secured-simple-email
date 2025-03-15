package org.simple.mail.server;

import java.io.IOException;
import java.net.Socket;

import org.simple.mail.util.Request;
import org.simple.mail.util.Response;
import org.simple.mail.util.TcpChannel;

public class ServerWorker implements Runnable {
	Socket socket;
	
	public ServerWorker(Socket s){
		this.socket = s;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		try {
			TcpChannel channel = new TcpChannel(socket);
			RequestProcessor processor = new RequestProcessor();
			while(true){
				Request request = new Request();
				if ((request = channel.receiveRequest()) == null )
					break;
				processor.setRequest(request);
				if(processor.process() < 0)
					break;
				Response response = processor.getResponse();
				if (response != null)
					channel.sendResponse(processor.getResponse());
			}
			socket.close();
				
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
