package latLock;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Date;
import java.util.Vector;

public class UsernameList {	
	public static final String FILENAME = "user.dat";

	private Vector<Username> usernames;
	private Date lastUpdate;
	
	public UsernameList(){
		usernames = new Vector<Username>();
	}

	public void read() {
		try {
			FileInputStream fileIn = new FileInputStream(FILENAME);
			ObjectInputStream in = new ObjectInputStream(fileIn);
			
			lastUpdate = (Date) in.readObject();
			
			Username u = (Username) in.readObject();
			while(u != null) {
				usernames.add(u);
				u = (Username) in.readObject();
				System.out.println(u.name);
			}
			
			in.close();
			fileIn.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void write() {
		try {
			FileOutputStream fileOut = new FileOutputStream(FILENAME);
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			
			out.writeObject(lastUpdate);
			
			for(int i = 0; i < usernames.size(); i++) {
				out.writeObject(usernames.get(i));
			}
			
			out.close();
			fileOut.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public boolean verify(String username_str) {
		for(int i = 0; i < usernames.size(); i++) {
			if(usernames.get(i).name == username_str) {
				return true;
			}
		}
		
		usernames.add(new Username(username_str));
		
		return false;
	}
	
	public Vector<Username> getNameAfter(Date date){
		Vector<Username> afters = new Vector<Username>();

		for(int i = 0; i < usernames.size(); i++) {
			if(usernames.get(i).submitTime.after(date)) {
				afters.add(usernames.get(i));
			}
		}
		
		return afters;
	}
}
