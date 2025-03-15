package org.simple.mail.server;

import java.sql.SQLException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import org.simple.mail.util.Command;
import org.simple.mail.util.Database;
import org.simple.mail.util.Mail;
import org.simple.mail.util.Request;
import org.simple.mail.util.Response;

public class RequestProcessor{ 
	private Request request;
	private Response response;
	private Mail mail;
	private Session session;
	private Database db;
	
	public RequestProcessor(){
		session = new Session();
		request = new Request();
		try {
			db = new Database(Database.DB_NAME, Database.ACCOUNT, Database.PASSWORD);
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
	
	public int process(){
		int ret = 0;
		
		if(session.getStatus() == Session.RECEIVING_MAIL)
			receiveMail();
		else{			
			String command = request.getCommand();
			if(command.compareTo(Command.DATA) == 0)
				doData();
			else if(command.compareTo(Command.DELETE) == 0)
				doDelete();
			else if(command.compareTo(Command.HELLO) == 0)
				doHello();
			else if(command.compareTo(Command.LIST) == 0)
				doList();
			else if(command.compareTo(Command.MAIL) == 0)
				doMail();
			else if(command.compareTo(Command.QUIT) == 0)
				ret = doQuit();
			else if(command.compareTo(Command.RETRIEVE) == 0)
				doRetrieve();
			else 
				doWrong();
		}			
			
		return ret;
	}
	
	public void doData(){
		response = new Response();
		if(session.getStatus() == Session.RECIPIENT_IDENTIFIED){
			mail.setTime(new Date());
			session.setStatus(Session.RECEIVING_MAIL);
			response.setContent(Response.SUCCESS, Response.DATA_SUCCESS);
		}
		else
			response.setContent(Response.ERROR, Response.BAD_SEQUENCE);
	}
	
	public void doDelete(){
		response = new Response();
		if(session.getStatus() == Session.USER_IDENTIFIED){
			int foundMail = 0; 
			foundMail = db.deleteMail(session.getUser(), Integer.parseInt(request.getParameter()));
			if(foundMail != 0)
				response.setContent(Response.SUCCESS, Response.DELETE_SUCCESS);
			else response.setContent(Response.ERROR, Response.DELETE_FAIL);
		}
		else response.setContent(Response.ERROR, Response.BAD_SEQUENCE);			
	}
	
	public void doHello(){
		response = new Response();
		session.setUser(request.getParameter());			
		response.setContent(Response.SUCCESS, Response.HELLO_SUCCESS);
	}
	
	public void doList(){
		response = new Response();
		if(session.getStatus() == Session.USER_IDENTIFIED){
			ArrayList<Mail> list = new ArrayList<Mail>();
			list = db.retrieveMailList(session.getUser());
			StringBuilder result = new StringBuilder();
			int size = list.size();
			result.append(size);
			for(Mail mail : list){
				result.append("\n");
				result.append(mail.getId());
				result.append(" ");
				DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy hh:mm:ss");
				result.append(dateFormat.format(mail.getReceivedTime()));
				result.append(" ");
				result.append(mail.getSender());				
			}
			response.setContent(Response.SUCCESS, result.toString());
		}
		else response.setContent(Response.ERROR, Response.BAD_SEQUENCE);
			
	}
	
	public void doMail(){
		response = new Response();
		if(session.getStatus() == Session.USER_IDENTIFIED || session.getStatus() == Session.RECIPIENT_IDENTIFIED){
			session.setStatus(Session.RECIPIENT_IDENTIFIED);
			mail = new Mail();
			mail.setSender(session.getUser());
			mail.setRecipient(request.getParameter());
			mail.setBody("");
			response.setContent(Response.SUCCESS, Response.MAIL_SUCCESS);
		}
		else response.setContent(Response.ERROR, Response.BAD_SEQUENCE);
	}
	
	public int doQuit(){
		return -1;
	}
	
	public void doRetrieve(){
		response = new Response();
		if(session.getStatus() == Session.USER_IDENTIFIED){
			Mail mail = db.retrieveMail(session.getUser(),Integer.parseInt(request.getParameter()));
			if(mail != null){
				StringBuilder result = new StringBuilder();
				String rawMail = mail.craftToString();
				result.append(rawMail.length());
				result.append("\n");
				result.append(rawMail);
				response.setContent(Response.SUCCESS, result.toString());				
			}
			else response.setContent(Response.ERROR, Response.RETRIEVE_FAIL);
		}
		else response.setContent(Response.ERROR, Response.BAD_SEQUENCE);				
	}
	
	public void doWrong(){
		response = new Response();
		response.setContent(Response.ERROR, Response.WRONG_SYNTAX);
	}
	
	private void receiveMail(){
		String line = request.getRaw();		
		if (line.compareTo(Mail.END_MAIL) != 0){
			response = null;
			StringBuilder builder = new StringBuilder();
			builder.append(mail.getBody() + "\n");
			builder.append(line);
			mail.setBody(builder.toString());
		}
		else{
			response = new Response();
			response.setContent(Response.SUCCESS, Response.DELIVERY_SUCCESS);
			db.insertMail(mail);
			session.setStatus(Session.USER_IDENTIFIED);
		}
	}
	
	public void setRequest(Request req){
		this.request = req;
	}
	
	public Response getResponse(){
		return this.response;
	}
}
