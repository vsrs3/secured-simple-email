package org.simple.mail.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

import org.simple.mail.util.Command;
import org.simple.mail.util.Mail;
import org.simple.mail.util.Request;
import org.simple.mail.util.Response;
import org.simple.mail.util.TcpChannel;

public class UserProcessor {
	private Socket socket;
	private Request request;
	private Response response;
	private TcpChannel channel;
	
	public UserProcessor(Socket sock){
		this.socket = sock;
		try {
			channel = new TcpChannel(socket);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public int process() throws IOException{
		String command = request.getCommand();
		channel.sendRequest(request);
		response = channel.receiveResponse();
		if(response != null){
			handleResponse(command);
			return 0;
		}
		else return -1;
	}
	
	public void setResponse(Response res){
		this.response = res;
	}
	
	public void setRequest(Request req){
		this.request = req;
	}
	
	private void handleResponse(String command) throws IOException{
		System.out.println("Receive: " + response.craftToString());
		
		String returnCode = response.getCode();
		if (returnCode.compareTo(Response.SUCCESS) == 0){
			if (command.compareToIgnoreCase(Command.DATA) == 0)
				doDataResponse();
			else if (command.compareToIgnoreCase(Command.LIST) == 0)
				doListResponse();
			else if (command.compareToIgnoreCase(Command.RETRIEVE) == 0)
				doRetrieveResponse();
		}
	}
	
	private void doDataResponse() throws IOException{
		System.out.println("Send: ");
		BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
			String line;
			
			do{
				line = user.readLine();
				channel.sendRequest(new Request(line));
			}while (line.compareTo(Mail.END_MAIL) != 0);
			
		response = channel.receiveResponse();
		System.out.println(response.craftToString());
	}
	
	private void doListResponse() throws IOException{
		StringBuilder builder = new StringBuilder();
		int numberOfMail = Integer.parseInt(response.getNotice());
		for(int i = 0; i < numberOfMail; i++)
			builder.append(channel.receiveLine());
		System.out.println(builder.toString());
	}
	
	private void doRetrieveResponse() throws IOException{
		StringBuilder builder = new StringBuilder();
		String line;
		int leftBytes = Integer.parseInt(response.getNotice()) + 1;
		while(leftBytes > 0){
			line = channel.receiveLine();
			builder.append(line);
			leftBytes = leftBytes - line.length();
		}
		System.out.println(builder.toString());
	}
}
