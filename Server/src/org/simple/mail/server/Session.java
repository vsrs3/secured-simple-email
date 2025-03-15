package org.simple.mail.server;

public class Session {
	public final static int USER_UNIDENTIFIED = 0;
	public final static int USER_IDENTIFIED = 1;
	public final static int RECIPIENT_IDENTIFIED = 2;
	public final static int RECEIVING_MAIL = 3;
	
	private String user;
	private int status;
	
	public Session(){
		this.status = USER_UNIDENTIFIED;
	}
	
	public void setUser(String user){
		this.user = user;
		this.status = USER_IDENTIFIED;
	}
	
	public void setStatus(int status){
		this.status = status;
	}
	
	public String getUser(){
		return this.user;
	}
	
	public int getStatus(){
		return this.status;
	}
}
