package org.simple.mail.util;

public class Request {
	private String raw;
	private String command;
	private String parameter;
	
	public Request(){}
	
	public Request(String messageString){
		this.raw = messageString;
		this.parse(raw);
	}
	
	public Request(String command, String parameter){
		this.command = command;
		this.parameter = parameter;
	}
	
	public String craftToString(){
		StringBuilder builder = new StringBuilder();
		builder.append(this.command);
		if (this.parameter.length() > 0){
			builder.append(IMessage.DEMILITER);
			builder.append(this.parameter);
		}
		
		return builder.toString();
	}
	public String getRaw(){
		return this.raw;
	}
	
	public String getCommand(){
		return this.command.toUpperCase();
	}
	
	public String getParameter(){
		return this.parameter;
	}
	
	private void parse(String messageString){
		messageString = messageString.trim();
		int firstSpace = messageString.indexOf(IMessage.DEMILITER);
		//Command has parameters
		if (firstSpace > 0){		
			command = messageString.substring(0, firstSpace);
			parameter = messageString.substring(firstSpace + 1).trim();
		}
		//Command has not parameters 
		else
		{
			command = messageString;
			parameter = "";
		}
	}
}
