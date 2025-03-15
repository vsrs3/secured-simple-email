package org.simple.mail.util;

public class Response implements IMessage{
	public final static String SUCCESS = "+OK";
	public final static String ERROR = "-ERR";
	public final static String HELLO_SUCCESS = "Welcome to server";
	public final static String HELLO_FAIL = "User is not found";
	public final static String MAIL_SUCCESS = "Recipient ok";
	public final static String MAIL_FAIL_NO_RECIPIENT = "Recipient is not found";
	public final static String DELETE_SUCCESS = "Mail is deleted";
	public final static String DELETE_FAIL = "Mail is not found";
	public final static String RETRIEVE_SUCCESS = "Mail is found";
	public final static String RETRIEVE_FAIL = "Mail is not found";
	public final static String WRONG_SYNTAX = "Wrong syntax";
	public final static String BAD_SEQUENCE = "Bad sequence of commands";
	
	private String code;
	private String notice;
	
	public Response(String message){
		this.parse(message);
	}
	@Override
	public String craftToString() {
		StringBuilder builder = new StringBuilder();
		builder.append(this.code);
		if (this.notice.length() > 0){
			builder.append(IMessage.DEMILITER);
			builder.append(this.notice);
		}
		
		return builder.toString();
	}

	@Override
	public void parse(String messageString) {
		messageString = messageString.trim();
		int firstSpace = messageString.indexOf(IMessage.DEMILITER);
		
		if (firstSpace > 0){
			this.code = messageString.substring(0, firstSpace);
			this.notice = messageString.substring(firstSpace + 1).trim();
		}
		else{
			this.code = messageString;
			this.notice = "";
		}
	}
	
	public String getCode(){
		return this.code;
	}
	
	public String getNotice(){
		return this.notice;
	}
	public void setContent(String code, String notice){
		this.code = code;
		this.notice = notice;
	}
	public void setCode(String code){
		this.code = code;
	}
	
	public void setNotice(String notice){
		this.notice = notice;
	}
}
