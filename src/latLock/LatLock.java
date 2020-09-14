package latLock;
 
import java.io.File;
import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.BoxLayout;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JPanel;
import java.awt.Color;
import java.awt.EventQueue;
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
	
	//file properties
    private static final String DEFAULT_WORKING_DIR = "/";
    public static final String LAT_FILE_EXT = ".lat";
	
	//visual properties
	private static final int WINDOW_WIDTH = 900;
	private static final int WINDOW_HEIGHT = 600;
	
	//visual panel instances
	ActionPanel work_panel, pass_panel;
			
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
	
	private void encrypt(char[] seed_str, File inFile) throws IOException, NtruException{
		//generate keys based on seed str
		Random prng = makePRNG(seed_str);
		NtruEncryptKey k = genKeys(prng);
		
        //encrypt the given file
        IO.encryptFile(k, prng, inFile, inFile.getPath()+LAT_FILE_EXT);
        
		//remove original file
		inFile.delete();
	}	
	
	private void decrypt(char[] seed_str, File inFile) throws IOException, NtruException{
		//generate keys based on seed str
		Random prng = makePRNG(seed_str);
		NtruEncryptKey k = genKeys(prng);
		
		//remove .lat from the input file path
		String out_path = inFile.getPath().substring(0, 
				inFile.getPath().length()-LAT_FILE_EXT.length());

        //decrypt the encryption output
        IO.decryptFile(k,  inFile, out_path);
        
		//remove encrypted file
		inFile.delete();
	}
	
    private LatLock() {
		setResizable(true);
		setFocusable(true);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		setSize(WINDOW_WIDTH, WINDOW_HEIGHT);
		
		setTitle("Lat");

		setBackground(Color.DARK_GRAY);
		
		// MAIN LAYOUT
        // .lat file selector
		LatSelector latSelector = new LatSelector();
		float size =  Math.round(latSelector.setDirectory(DEFAULT_WORKING_DIR)/10000.0f)/100.0f;
		setTitle(DEFAULT_WORKING_DIR + " - " + size + " MB - Lat");
		
		//create action panel to select working directory
        work_panel = new ActionPanel("Current Directory", DEFAULT_WORKING_DIR, "...", false,
	        new ActionListener() {
				@Override public void actionPerformed(ActionEvent a) {
	                //open file chooser and select a file
					JFileChooser chsr = new JFileChooser();
					chsr.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);;
					if(chsr.showOpenDialog(getParent()) == JFileChooser.APPROVE_OPTION) {
						String dir = chsr.getSelectedFile().getPath();
						work_panel.setValue(dir);
						
						float size = Math.round(latSelector.setDirectory(dir)/10000.0f)/100.0f;
						setTitle(dir + " - " + size + " MB - Lat");
						
						repaint();
					}
	            }
	        });

        //create action panel to enter password and lock/unlock
        pass_panel = new ActionPanel("Password", "", "Lock/Unlock", true,
	        new ActionListener() {
				@Override public void actionPerformed(ActionEvent a) {
					File f = latSelector.getSelectedFile();
					if(f == null) {
						System.out.println("ERROR: Decrypt failed: No file selected");
						return;
					}
					
					if(f.getName().endsWith(LAT_FILE_EXT)) {
		                //Unlock
		                try {
							decrypt(pass_panel.getValue().toCharArray(), f);					

							//clear password field
							pass_panel.setValue("");
							
							System.out.println("Successfully decrypted from "+f.getName());
						} catch (IOException | NtruException e) {
							System.out.println("ERROR: Decrypt failed: "+e.getLocalizedMessage());
							e.printStackTrace();
						}
					} else {
		                //Lock
		                try {
		                	//encrypt using value of password field
							encrypt(pass_panel.getValue().toCharArray(), f);
							
							//clear password field
							pass_panel.setValue("");
							
							System.out.println("Successfully encrypted to "+f.getName());
						} catch (IOException | NtruException e) {
							System.out.println("ERROR: Encrypt failed: "+ e.getLocalizedMessage());
							e.printStackTrace();
						}
					}
	            }
	        });
 
		// PANEL STRUCTURE
		// basic panel creation
		JPanel panel_main = new JPanel();
		panel_main.setLayout(new BoxLayout(panel_main, BoxLayout.PAGE_AXIS));
		panel_main.setBackground(Color.DARK_GRAY);

		//action panel creation
		JPanel panel_action = new JPanel();
		panel_action.setLayout(new BoxLayout(panel_action, BoxLayout.X_AXIS));
		panel_action.setBackground(Color.DARK_GRAY);
		
		//some generic objects for padding		
		JPanel h_padding_a = new JPanel();
		h_padding_a.setBackground(Color.DARK_GRAY);
		
		JPanel h_padding_b = new JPanel();
		h_padding_b.setBackground(Color.DARK_GRAY);

		JPanel h_padding_c = new JPanel();
		h_padding_c.setBackground(Color.DARK_GRAY);
		
        JPanel v_padding_a = new JPanel();
		v_padding_a.setBackground(Color.DARK_GRAY);
		
        JPanel v_padding_b = new JPanel();
		v_padding_b.setBackground(Color.DARK_GRAY);

		// add everything
		panel_main.add(latSelector);
        panel_main.add(v_padding_a);

        panel_action.add(h_padding_a);
        panel_action.add(work_panel);
        panel_action.add(h_padding_b);
        panel_action.add(pass_panel);
        panel_action.add(h_padding_c);
        
		panel_main.add(panel_action);
		
		panel_main.add(v_padding_b);
		
		add(panel_main);
		
		new Timer().schedule(new TimerTask() {
			@Override public void run() {
				latSelector.refresh();
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
