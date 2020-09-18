package latLock;
 
import javax.swing.JFrame;

import java.awt.Color;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Timer;
import java.util.TimerTask;

public class LatLock extends JFrame {
	private static final long serialVersionUID = 1L;
	
	public static final Color COLOR = new Color(8, 7, 8);
	public static final String DEFAULT_TITLE = "LatLock";
	
	public static final String REMOTE_HOST = "localhost";
	public static final int REMOTE_PORT = 4444;
	
	// behind the scenes instances
	UsernameList userList;
	WebTransfer webTransfer;
	
	//sub-panels
	LoginPanel loginPanel;
	MainPanel mainPanel;
	
    private LatLock() {
		setResizable(false);
		setFocusable(true);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setTitle(DEFAULT_TITLE);
		
		// setup a web transfer connection
		webTransfer = new WebTransfer();
		webTransfer.connect(REMOTE_HOST, REMOTE_PORT);
		
		// exchange the username list file with the remote server
		webTransfer.exchangeFile(UsernameList.FILENAME);	
		
		// read the username list from the file you just saved
		userList = new UsernameList();
		userList.read();
		
		// create the login panel
		loginPanel = new LoginPanel(
			new ActionListener() {
				@Override public void actionPerformed(ActionEvent arg0) {
					// check if the username exists already
					userList.verify(loginPanel.getUsername());
					
					// write the username to file
					userList.write();
					
					// exchange the username list file with the remote server again then dc
					webTransfer.exchangeFile(UsernameList.FILENAME);	
					webTransfer.disconnect();
					
					//switch to the main panel
					setResizable(true);
					
					mainPanel = new MainPanel(loginPanel.getCredentialSeed());

					remove(loginPanel);
					add(mainPanel);
					pack();
				}
			});
		
		add(loginPanel);
		pack();
		
		//set the refresh operation to occur every second
		new Timer().schedule(new TimerTask() {
			@Override public void run() {
				if(mainPanel != null) {
					mainPanel.refresh();
					setTitle(mainPanel.title);
				}
			}
		}, 100, 1000);
	}
	
	public static void main(String[] args) {
             
        EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				LatLock app = new LatLock();
				app.setLocationRelativeTo(null);
				app.setVisible(true);
			}
		});
    }
}
