package latLock;

public class WebTransfer {	
	public static final char STATUS_OK = 0;
	public static final char STATUS_CONNECTED = 1;
	public static final char STATUS_FILE_SENT = 2;
	public static final char STATUS_CON_ERR = 3;
	public static final char STATUS_FILE_ERR = 4;

	public char status = STATUS_OK;

	public WebTransfer(){

	}

	public void connect(String server_addr, Runnable cb) {

	}

	public void disconnect() {

	}

	public void sendFile(File f, Runnable cb) {

	}

	public void sendNewUsers(Vector<Username> new_users){

	}
}

