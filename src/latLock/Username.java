package latLock;

import java.io.Serializable;
import java.util.Date;

public class Username implements Serializable{	
	private static final long serialVersionUID = 1L;
	
	public Date submitTime;
	public String name;
	
	public Username(String name){
		this.name = name;
		
		submitTime = new Date();
	}
}
