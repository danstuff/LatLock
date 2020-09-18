package latLock;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionListener;

import javax.swing.AbstractButton;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class LoginPanel extends JPanel{
	private static final long serialVersionUID = 1L;
	
	//Window properties
	private static final int WIDTH = 400;
	private static final int HEIGHT = 300;
	
	//Security properites
	private static final int SEED_LEN = 32;
	
	//Sub-panels
	private JTextField header, userField, passField;
	private JButton button;

	public LoginPanel(ActionListener button_act) {
		setBackground(LatLock.COLOR);
		
		// Set up panel size
		setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
		setPreferredSize(new Dimension(WIDTH, HEIGHT));
		
    	// Create fonts
		Font header_font = new Font("Sans-Serif", Font.PLAIN, 14);
		Font edit_font = new Font("Sans-Serif", Font.PLAIN, 12);
		
        // Create header
        header = new JTextField();
		header.setHorizontalAlignment(JTextField.LEFT);
		header.setEditable(false);
		header.setBorder(null);

		header.setFont(header_font);
		header.setText("Log In or Create Your Account");
		
		header.setForeground(Color.WHITE);
		header.setBackground(LatLock.COLOR);
        
        // Create username field
		userField = new JTextField();
		userField.setBorder(null);
		userField.setFont(edit_font);
		
        // Create password field
		passField = new JPasswordField();
		passField.setBorder(null);
		passField.setFont(edit_font);

        // Create button
        button = new JButton("Submit");
		button.setVerticalTextPosition(AbstractButton.CENTER);
		button.setHorizontalTextPosition(AbstractButton.CENTER);
		
		button.addActionListener(button_act);
		
		button.setBackground(Color.LIGHT_GRAY);
		        
        // Create horizontal inner panel
		JPanel button_panel = new JPanel(new BorderLayout(0,0));
		button_panel.add(button);

		//create some padding objects
		JPanel[] padding = new JPanel[5];
		for(int i = 0; i < 5; i++) {
			padding[i] = new JPanel();
			padding[i].setBackground(LatLock.COLOR);
		}
		
		JPanel vertPanel = new JPanel();
		vertPanel.setLayout(new BoxLayout(vertPanel, BoxLayout.Y_AXIS));
		vertPanel.setBackground(LatLock.COLOR);

        vertPanel.add(header);
        
        vertPanel.add(userField);
        
        vertPanel.add(padding[0]);
        
        vertPanel.add(passField);
        
        vertPanel.add(padding[1]);
        
        vertPanel.add(button_panel);
        
        vertPanel.add(padding[2]);
        
        add(padding[3]);
        
        add(vertPanel);
        
        add(padding[4]);
	}

	public byte[] getCredentialSeed() {
		char[] u = userField.getText().toCharArray();
		char[] p = passField.getText().toCharArray();
		
		byte[] res = new byte[SEED_LEN];
		
		for(int i = 0; i < SEED_LEN; i++) {
			char a = u[i % u.length];
			char b = p[i % p.length];
			
			res[i] = (byte) (a % b >> (b/a));
		}
		
		return res;
	}
	
	public String getUsername(){ {
		return userField.getText();
	}
	}
}
