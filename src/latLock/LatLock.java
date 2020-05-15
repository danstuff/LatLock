package latLock;
 
import java.io.IOException;

import javax.swing.AbstractButton;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Font;
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
	
	private static final String PRI_KEY_FILE = "myPrivateKey.key";
	private static final String PUB_KEY_FILE = "myPublicKey.key";
	
	private static final String ENC_OUT_FILE = "mySafe.lat";
	
	//visual properties
	private static final int WINDOW_WIDTH = 400;
	private static final int WINDOW_HEIGHT = 200;
	
	private Random makePRNG(String seed_str) {
		//set up PRNG with a seed given as a char string
        byte seed[] = new byte[SEED_LEN];

		//loop through string and convert chars to bytes
        for(int i = 0; i < SEED_LEN; i++) {
        	int j = i % seed_str.length();
        	seed[i] = (byte) seed_str.charAt(j);
        }
        
        return new Random(seed);
	}
	
	private void genKeys(Random prng) throws IOException, NtruException {
        //generate public and private keys
        OID oid = OID.valueOf(SECURITY_TYPE);
        IO.setupNtruEncryptKey(prng, oid, PUB_KEY_FILE, PRI_KEY_FILE);
	}
	
	private void encrypt(String seed_str, String plain_path) throws IOException, NtruException{
		//generate keys based on seed str
		Random prng = makePRNG(seed_str);
		genKeys(prng);
		
        //encrypt the given file
        NtruEncryptKey pubKey = IO.loadKey(PUB_KEY_FILE);
        IO.encryptFile(pubKey, prng, plain_path, ENC_OUT_FILE);
	}	
	
	private void decrypt(String seed_str, String plain_path) throws IOException, NtruException{
		//generate keys based on seed str
		genKeys(makePRNG(seed_str));
		
        //decrypt the encryption output
        NtruEncryptKey privKey = IO.loadKey(PRI_KEY_FILE);
        IO.decryptFile(privKey, ENC_OUT_FILE, plain_path);
	}

	private void makeGUI() {
		setResizable(false);
		setFocusable(true);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		setSize(WINDOW_WIDTH, WINDOW_HEIGHT);

		Font title_font = new Font("Serif", Font.ITALIC, 20);
		Font entry_font = new Font(Font.MONOSPACED, Font.PLAIN, 16);

		// BUTTONS AND FIELDS
		// title area
		JTextField title = new JTextField();
		title.setHorizontalAlignment(JTextField.CENTER);
		title.setEditable(false);
		title.setBorder(null);

		title.setFont(title_font);

		title.setText("LatLock v0.1 Alpha");
		
		// seed entry field
		JTextField seed_field = new JTextField();
		seed_field.setFont(entry_font);
		seed_field.setToolTipText("Seed");
		seed_field.setText("Seed");
		
		// field for file containing plaintext input/output
		JTextField plaintext_field = new JTextField();
		plaintext_field.setFont(entry_font);
		plaintext_field.setToolTipText("Plaintext File");
		plaintext_field.setText("Plaintext File");
		
		// encrypt button
		JButton enc_button = new JButton("Encrypt");
		enc_button.setVerticalTextPosition(AbstractButton.CENTER);
		enc_button.setHorizontalTextPosition(AbstractButton.CENTER);
		
		enc_button.addActionListener(new ActionListener() {
			@Override public void actionPerformed(ActionEvent a) {
				try {
					encrypt(seed_field.getText(), plaintext_field.getText());
				} catch (IOException | NtruException e) {
					e.printStackTrace();
				}
			}
		});
		
		// decrypt button
		JButton dec_button = new JButton("Decrypt");
		dec_button.setVerticalTextPosition(AbstractButton.CENTER);
		dec_button.setHorizontalTextPosition(AbstractButton.CENTER);
		
		dec_button.addActionListener(new ActionListener() {
			@Override public void actionPerformed(ActionEvent a) {
				try {
					decrypt(seed_field.getText(), plaintext_field.getText());
				} catch (IOException | NtruException e) {
					e.printStackTrace();
				}
			}
		});
		
		// PANEL STRUCTURE
		// basic panel creation
		JPanel panel_rows = new JPanel();
		panel_rows.setLayout(new BoxLayout(panel_rows, BoxLayout.PAGE_AXIS));
		panel_rows.setSize(WINDOW_WIDTH, WINDOW_HEIGHT);

		//button panel creation
		JPanel buttons = new JPanel();
		buttons.setLayout(new BoxLayout(buttons, BoxLayout.X_AXIS));

		//some generic objects for padding
		JPanel v_padding_a = new JPanel();
		v_padding_a.setSize(new Dimension(100, 50));

		JPanel v_padding_b = new JPanel();
		v_padding_b.setSize(new Dimension(100, 50));

		// add everything
		panel_rows.add(title);
		panel_rows.add(v_padding_a);
		panel_rows.add(seed_field);
		panel_rows.add(plaintext_field);
		panel_rows.add(v_padding_b);
		
		buttons.add(enc_button);
		buttons.add(dec_button);
		
		panel_rows.add(buttons);

		add(panel_rows);
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