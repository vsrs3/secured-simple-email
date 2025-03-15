package org.simple.mail.util;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;

public class TcpChannel {
	private Socket socket;
	private BufferedReader in;
	private PrintWriter out ;
	
	public TcpChannel(Socket s) throws IOException{
		this.socket = s;
		in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
	}
	
	public int sendRequest(Request request){
		String message = request.getRaw();
		out.println(message);
		out.flush();
		return message.length();
	}
	
	public Response receiveResponse() throws IOException{
		Response response = null;
		String line;
		if ((line=in.readLine()) != null){
			response = new Response(line);
		}
		return response;
	}

	public String receiveLine() throws IOException{
		String line = null;
			if ((line = in.readLine()) != null)
				return (line + "\n");
		return line;
	}
}
