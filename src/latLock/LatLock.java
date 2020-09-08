package latLock;
 
import java.io.File;
import java.io.IOException;

import javax.swing.AbstractButton;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;

public class LatLock extends JFrame {
	//base class for the GUI
	private static final long serialVersionUID = 1L;
	
	//security properties
	private static final int SEED_LEN = 32;
	
	private static final String SECURITY_TYPE = "ees1499ep1";
    private static final String DEFAULT_WORKING_DIR = "/";
	
	//visual properties
	private static final int WINDOW_WIDTH = 400;
	private static final int WINDOW_HEIGHT = 200;
	
	private Random makePRNG(char[] seed_str) {
		//set up PRNG with a seed given as a char string
        byte seed[] = new byte[SEED_LEN];
        
        if(seed_str.length == 0) {
        	return new Random(seed);
        }

		//loop through string and convert chars to bytes
        for(int i = 0; i < SEED_LEN; i++) {
        	int j = i % seed_str.length;
        	seed[i] = (byte) seed_str[j];
        }
        
        return new Random(seed);
	}
	
	private NtruEncryptKey genKeys(Random prng) throws IOException, NtruException {
        //generate public and private keys
        OID oid = OID.valueOf(SECURITY_TYPE);
        return NtruEncryptKey.genKey(oid, prng);
	}
	
	private void encrypt(char[] seed_str, String plain_path) throws IOException, NtruException{
		//generate keys based on seed str
		Random prng = makePRNG(seed_str);
		NtruEncryptKey k = genKeys(prng);
		
        //encrypt the given file
        IO.encryptFile(k, prng, plain_path, ENC_OUT_FILE);
	}	
	
	private void decrypt(char[] seed_str, String plain_path) throws IOException, NtruException{
		//generate keys based on seed str
		Random prng = makePRNG(seed_str);
		NtruEncryptKey k = genKeys(prng);
		
        //decrypt the encryption output
        IO.decryptFile(k, ENC_OUT_FILE, plain_path);
	}
	
    private JPanel makeActionPanel(String header_text, String field_text, String button_text,
                                   ActionListener button_act){
        // Create header
        JTextField header = new JTextField();
		header.setHorizontalAlignment(JTextField.LEFT);
		header.setEditable(false);
		header.setBorder(null);

		header.setFont(header_font);
		header.setText(header_text);
        
        // Create selector field
        JTextField field = new JTextField();
		field.setFont(entry_font);
		field.setToolTipText("Select a Folder");

        // Create button
        JButton button = new JButton(button_text);
		button.setVerticalTextPosition(AbstractButton.CENTER);
		button.setHorizontalTextPosition(AbstractButton.CENTER);
		
		button.addActionListener(al);
        
        // Create vertical and horizontal panel
        JPanel option_panel = new JPanel();
		option_panel.setLayout(new BoxLayout(option_panel, BoxLayout.Y_AXIS));
		option_panel.setSize(160, 80);

        JPanel inner_panel = new JPanel();
        inner_panel.setLayout(new BoxLayout(inner_panel, BoxLayout.X_AXIS));
        inner_panel.setSize(160, 40);

        option_panel.add(header);
        
        inner_panel.add(field);
        inner_panel.add(button);

        option_panel.add(inner_panel);

        return option_panel;
    }
	
	private void makeGUI() {
		setResizable(false);
		setFocusable(true);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		setSize(WINDOW_WIDTH, WINDOW_HEIGHT);

        //Create fonts
		Font header_font = new Font("Sans-Serif", Font.PLAIN, 8);
		Font edit_text_font = new Font("Sans-Serif", Font.PLAIN, 14);
		Font button_font = new Font("Sans-Serif", Font.PLAIN, 16);

		Font file_font = new Font("Sans-Serif", Font.PLAIN, 12);

		// BUTTONS AND FIELDS
        // .lat file selector
        // TODO implement this
        LatSelector lat_selector = new LatSelector(DEFAULT_WORKING_DIR);
        lat_selector.setCallback(new LatListener() {
            @Override public void latFileSelected(String filename){
                working_filename = filename;
            }
        });

        JPanel work_panel = makeActionPanel("Working Directory", "Choose a Folder", "...",
        new ActionListener() {
			@Override public void actionPerformed(ActionEvent a) {
                //open file chooser and select a file
				JFileChooser chsr = new JFileChooser();
				if(chsr.showOpenDialog(getParent()) == JFileChooser.APPROVE_OPTION) {
					plaintext_field.setText(chsr.getSelectedFile().getPath());
				}
            }
        });

        JPanel pass_panel = makeActionPanel("Password", "", "Lock/Unlock",
        new ActionListener() {
			@Override public void actionPerformed(ActionEvent a) {
                //Lock
                try {
					encrypt(seed_field.getPassword(), plaintext_field.getText());
					
					//remove original file
					File f = new File(plaintext_field.getText());
					f.delete();
					
					//clear password field
					seed_field.setText("");
					
					System.out.println("Successfully encrypted to "+ENC_OUT_FILE);
				} catch (IOException | NtruException e) {
					System.out.println("ERROR: Encrypt failed: "+ e.getLocalizedMessage());
					e.printStackTrace();
				}

                //Unlock
                try {
					decrypt(seed_field.getPassword(), plaintext_field.getText());					
					
					//clear password field
					seed_field.setText("");
					
					System.out.println("Successfully decrypted from "+ENC_OUT_FILE);
				} catch (IOException | NtruException e) {
					System.out.println("ERROR: Decrypt failed: "+e.getLocalizedMessage());
					e.printStackTrace();
				}
            }
        });
 
		// PANEL STRUCTURE
		// basic panel creation
		JPanel panel_main = new JPanel();
		panel_main.setLayout(new BoxLayout(panel_main, BoxLayout.PAGE_AXIS));
		panel_main.setSize(WINDOW_WIDTH, WINDOW_HEIGHT);

		//action panel creation
		JPanel panel_action = new JPanel();
		panel_action.setLayout(new BoxLayout(panel_action, BoxLayout.X_AXIS));
		
		//some generic objects for padding
		JPanel h_padding = new JPanel();
		h_padding.setSize(new Dimension(25, 50));
        
        JPanel v_padding = new JPanel();
		v_padding.setSize(new Dimension(WINDOW_WIDTH, 16));

		// add everything
		panel_main.add(lat_selector);
        panel_main.add(v_padding);

        panel_action.add(work_panel);
        panel_action.add(h_padding);
        panel_action.add(pass_panel);

		panel_main.add(panel_action);
		
		add(panel_main);
	}
	
	public static void main(String[] args) {
             
        EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				LatLock app = new LatLock();
				app.makeGUI();
				app.setLocationRelativeTo(null);
				app.setVisible(true);
			}
		});
    }
}
