package latLock;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.Socket;

public class WebTransfer {	
	private Socket sock;

	public WebTransfer(){}
	
	public boolean connect(String host, int port) {
		try {
			sock = new Socket(host, port);
			
			if(sock.isConnected()) {
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
	}

	public boolean disconnect() {
		try {
			sock.close();
			return true;
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
	}

	public boolean exchangeFile(String filename) {
		try {
			FileInputStream fileIn = new FileInputStream(filename);
			DataOutputStream dataOut = new DataOutputStream(sock.getOutputStream());
			
			int count;
			byte[] buf = new byte[8192];
			while((count = fileIn.read(buf)) > 0) {
				dataOut.write(buf, 0, count);
			}
			
			fileIn.close();
			dataOut.close();

			DataInputStream dataIn = new DataInputStream(sock.getInputStream());
			FileOutputStream fileOut = new FileOutputStream(filename);
			
			count = 0;
			buf = new byte[8192];
			while((count = dataIn.read(buf)) > 0) {
				fileOut.write(buf, 0, count);
			}
			
			fileOut.close();
			dataIn.close();
			
			return true;
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
	}
}

