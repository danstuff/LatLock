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
	
	//sub-panels
	LoginPanel loginPanel;
	MainPanel mainPanel;
	
    private LatLock() {
		setResizable(false);
		setFocusable(true);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setTitle(DEFAULT_TITLE);
		
		loginPanel = new LoginPanel(
			new ActionListener() {
				@Override public void actionPerformed(ActionEvent arg0) {
					
					
					mainPanel = new MainPanel(loginPanel.getCredentialSeed());
					remove(loginPanel);
					setResizable(true);
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
