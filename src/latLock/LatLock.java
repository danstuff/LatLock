package latLock;
 
import java.io.File;
import java.io.IOException;

import javax.swing.BoxLayout;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JPanel;
import java.awt.Dimension;
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
    private static final String DEFAULT_WORKING_DIR = "/";
    private static final String LAT_FILE_EXT = ".lat";
	
	//visual properties
	private static final int WINDOW_WIDTH = 400;
	private static final int WINDOW_HEIGHT = 200;
	
	//the current filename and folder selected
	private static String working_filename = "";
	private static String working_directory = DEFAULT_WORKING_DIR;
			
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
	
	private void encrypt(char[] seed_str) throws IOException, NtruException{
		//generate keys based on seed str
		Random prng = makePRNG(seed_str);
		NtruEncryptKey k = genKeys(prng);
		
        //encrypt the given file
        IO.encryptFile(k, prng,
        		working_directory+working_filename, 
        		working_directory+working_filename+LAT_FILE_EXT);
        
		//remove original file
		File f = new File(working_directory+working_filename);
		f.delete();
	}	
	
	private void decrypt(char[] seed_str) throws IOException, NtruException{
		//generate keys based on seed str
		Random prng = makePRNG(seed_str);
		NtruEncryptKey k = genKeys(prng);
		
        //decrypt the encryption output
        IO.decryptFile(k, 
        		working_directory+working_filename+LAT_FILE_EXT, 
        		working_directory+working_filename);
        
		//remove encrypted file
		File f = new File(working_directory+working_filename+LAT_FILE_EXT);
		f.delete();
	}
	
    private LatLock() {
		setResizable(false);
		setFocusable(true);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		setSize(WINDOW_WIDTH, WINDOW_HEIGHT);

		// MAIN LAYOUT
        // .lat file selector
        // TODO implement this
        /*LatSelector lat_selector = new LatSelector(DEFAULT_WORKING_DIR);
        lat_selector.setCallback(new LatListener() {
            @Override public void latFileSelected(String filename){
                working_filename = filename;
            }
        });*/

		//create action panel to select working directory
        ActionPanel work_panel = new ActionPanel("Working Directory", "...", false,
        new ActionListener() {
			@Override public void actionPerformed(ActionEvent a) {
                //open file chooser and select a file
				JFileChooser chsr = new JFileChooser();
				if(chsr.showOpenDialog(getParent()) == JFileChooser.APPROVE_OPTION) {
					working_directory = chsr.getSelectedFile().getPath();
				}
            }
        });

        //create action panel to enter password and lock/unlock
        ActionPanel pass_panel = new ActionPanel("Password", "Lock/Unlock", true,
        new ActionListener() {
			@Override public void actionPerformed(ActionEvent a) {
                //Lock
                try {
                	//TODO
					encrypt("ABCD".toCharArray());
					
					//TODO clear password field
					//seed_field.setText("");
					
					System.out.println("Successfully encrypted to "+working_filename);
				} catch (IOException | NtruException e) {
					System.out.println("ERROR: Encrypt failed: "+ e.getLocalizedMessage());
					e.printStackTrace();
				}

                //Unlock
                try {
                	//TODO
					decrypt("ABCD".toCharArray());					
					
					//TODO clear password field
					//seed_field.setText("");
					
					System.out.println("Successfully decrypted from "+working_filename);
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
		//panel_main.add(lat_selector);
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
				app.setLocationRelativeTo(null);
				app.setVisible(true);
			}
		});
    }
}
