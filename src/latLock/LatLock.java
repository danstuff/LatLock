package latLock;
 
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
	private static final String ENC_OUT_FILE = "mySafe.lat";
	
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

	private JTextField makeHeader(String text, int align, Font font) {
		JTextField field = new JTextField();
		field.setHorizontalAlignment(align);
		field.setEditable(false);
		field.setBorder(null);

		field.setFont(font);

		field.setText(text);
		
		return field;
	}
	
	private JButton makeButton(String text, ActionListener al) {
		JButton btn = new JButton(text);
		btn.setVerticalTextPosition(AbstractButton.CENTER);
		btn.setHorizontalTextPosition(AbstractButton.CENTER);
		
		btn.addActionListener(al);
		
		return btn;
	}
	
	private void makeGUI() {
		setResizable(false);
		setFocusable(true);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		setSize(WINDOW_WIDTH, WINDOW_HEIGHT);

		Font title_font = new Font("Sans-Serif", Font.PLAIN, 20);
		Font header_font = new Font("Sans-Serif", Font.PLAIN, 12);
		Font entry_font = new Font(Font.MONOSPACED, Font.PLAIN, 16);

		// BUTTONS AND FIELDS
		// title area
		JTextField title = makeHeader("LatLock v0.2 Alpha", JTextField.CENTER, title_font);
		
		// plaintext header
		JTextField plain_head = makeHeader("  Plaintext File  ", JTextField.CENTER, header_font);
		
		// field for file containing plaintext input/output
		JTextField plaintext_field = new JTextField();
		plaintext_field.setFont(entry_font);
		plaintext_field.setToolTipText("Plaintext File");
		
		// field for choosing a plaintext file
		JButton plain_button = makeButton("...", new ActionListener() {
			@Override public void actionPerformed(ActionEvent a) {
				//open file chooser and select a file
				JFileChooser chsr = new JFileChooser();
				if(chsr.showOpenDialog(getParent()) == JFileChooser.APPROVE_OPTION) {
					plaintext_field.setText(chsr.getSelectedFile().getPath());
				}
			}
		});
		
		// seed header
		JTextField seed_head = makeHeader("  Password  ", JTextField.CENTER, header_font);
		
		// seed entry field
		JPasswordField seed_field = new JPasswordField();
		seed_field.setFont(entry_font);
		seed_field.setToolTipText("Password");		
		
		// output message
		JTextField output = makeHeader("", JTextField.LEFT, header_font);
		
		// encrypt button
		JButton enc_button = makeButton("Encrypt", new ActionListener() {
			@Override public void actionPerformed(ActionEvent a) {
				try {
					encrypt(seed_field.getPassword(), plaintext_field.getText());
					output.setText("  Successfully encrypted to "+ENC_OUT_FILE);
				} catch (IOException | NtruException e) {
					output.setText("  ERROR: Encrypt failed: "+ e.getLocalizedMessage());
					e.printStackTrace();
				}
			}
		});
		
		// decrypt button
		JButton dec_button = makeButton("Decrypt", new ActionListener() {
			@Override public void actionPerformed(ActionEvent a) {
				try {
					decrypt(seed_field.getPassword(), plaintext_field.getText());
					output.setText("  Successfully decrypted from "+ENC_OUT_FILE);
				} catch (IOException | NtruException e) {
					output.setText("  ERROR: Decrypt failed: "+e.getLocalizedMessage());
					e.printStackTrace();
				}
			}
		});

		// PANEL STRUCTURE
		// basic panel creation
		JPanel panel_rows = new JPanel();
		panel_rows.setLayout(new BoxLayout(panel_rows, BoxLayout.PAGE_AXIS));
		panel_rows.setSize(WINDOW_WIDTH, WINDOW_HEIGHT);

		//password panel creation
		JPanel panel_seed = new JPanel();
		panel_seed.setLayout(new BorderLayout());
		
		//plaintext file panel creation
		JPanel panel_plain = new JPanel();
		panel_plain.setLayout(new BorderLayout());
		
		//button panel creation
		JPanel buttons = new JPanel();
		buttons.setLayout(new BoxLayout(buttons, BoxLayout.X_AXIS));

		//some generic objects for padding
		JPanel v_padding_a = new JPanel();
		v_padding_a.setSize(new Dimension(100, 50));

		JPanel v_padding_b = new JPanel();
		v_padding_b.setSize(new Dimension(100, 50));
		
		JPanel v_padding_c = new JPanel();
		v_padding_c.setSize(new Dimension(100, 50));

		// add everything
		panel_rows.add(title);
		panel_rows.add(v_padding_a);
		
		panel_plain.add(plain_head, BorderLayout.WEST);
		panel_plain.add(plaintext_field, BorderLayout.CENTER);
		panel_plain.add(plain_button, BorderLayout.EAST);
		
		panel_rows.add(panel_plain);
		
		panel_seed.add(seed_head, BorderLayout.WEST);
		panel_seed.add(seed_field, BorderLayout.CENTER);
		
		panel_rows.add(panel_seed);
		
		panel_rows.add(v_padding_b);
		
		buttons.add(enc_button);
		buttons.add(dec_button);
		
		panel_rows.add(buttons);
		
		panel_rows.add(v_padding_c);
		
		panel_rows.add(output);

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