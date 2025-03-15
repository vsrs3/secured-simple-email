package org.simple.mail.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Mail {
	public final static String FROM = "FROM: "; 
	public final static String TO = "TO: ";
	public final static String DATE = "DATE: ";
	public final static String END_MAIL = ".";
	
	private int id;
	private String sender;
	private String recipient;
	private Date receivedTime;
	private String body;
	

	public String craftToString(){
		StringBuilder builder = new StringBuilder();
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");  
		
		builder.append(FROM + sender + "\n");
		builder.append(TO + recipient + "\n");
		builder.append(DATE + dateFormat.format(receivedTime)+ "\n");
		builder.append(body);
		return builder.toString();
	}
	
	public void setId(int id){
		this.id = id;
	}
	
	public void setSender(String sender){
		this.sender = sender.toLowerCase();
	}
	
	public void setRecipient(String recipient){
		this.recipient = recipient.toLowerCase();
	}
	
	public void setBody(String body){
		this.body = body;
	}
	
	public void setTime(Date time){
		this.receivedTime = time;

	}
	public int getId(){
		return this.id;
	}
	
	public String getSender(){
		return this.sender;
	}
	
	public String getRecipient(){
		return this.recipient;
	}
	
	public String getBody(){
		return this.body;
	}
	
	public Date getReceivedTime(){
		return this.receivedTime;
	}
	
}
