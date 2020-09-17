package latLock;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JPanel;

import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;

public class MainPanel extends JPanel{
	private static final long serialVersionUID = 1L;
	
	//Window properties
	private static final int WIDTH = 900;
	private static final int HEIGHT = 600;
	
	//File properties
    private static final String DEFAULT_WORKING_DIR = "/";
    public static final String LAT_FILE_EXT = ".lat";
    
    //Security properties
	private static final String SECURITY_TYPE = "ees1499ep1";

	
    //Where your login info is stored from login panel
    private byte[] credentials;
    
    //To be used as the window title
    public String title = LatLock.DEFAULT_TITLE;
    
    //Sub-panels
	public SelectorPanel selectorPanel;
	
	public JPanel statHolderPanel;
	
	public StatPanel fileStatPanel;
	public JButton lockButton, workingDirButton;
	
	private NtruEncryptKey genKeys(Random prng) throws IOException, NtruException {
        //generate public and private keys
        OID oid = OID.valueOf(SECURITY_TYPE);
        return NtruEncryptKey.genKey(oid, prng);
	}
	
	private void encrypt(File inFile) throws IOException, NtruException{
		//generate keys based on seed str
		Random prng = new Random(credentials);
		NtruEncryptKey k = genKeys(prng);
		
        //encrypt the given file
        IO.encryptFile(k, prng, inFile, inFile.getPath()+LAT_FILE_EXT);
        
		//remove original file
		inFile.delete();
	}	
	
	private void decrypt(File inFile) throws IOException, NtruException{
		//generate keys based on seed str
		Random prng = new Random(credentials);
		NtruEncryptKey k = genKeys(prng);
		
		//remove .lat from the input file path
		String out_path = inFile.getPath().substring(0, 
				inFile.getPath().length()-LAT_FILE_EXT.length());

        //decrypt the encryption output
        IO.decryptFile(k,  inFile, out_path);
        
		//remove encrypted file
		inFile.delete();
	}
	
	public MainPanel(byte[] credentials) {
		this.credentials = credentials;
		
		setPreferredSize(new Dimension(WIDTH, HEIGHT));
		setBackground(LatLock.COLOR);
		setLayout(new BoxLayout(this, BoxLayout.PAGE_AXIS));
		
		//Create selector panel
		selectorPanel = new SelectorPanel();
		float size =  Math.round(selectorPanel.setDirectory(DEFAULT_WORKING_DIR)/10000.0f)/100.0f;
		title = DEFAULT_WORKING_DIR + " - " + size + " MB - Lat";
		
		//create file status panel
		fileStatPanel = new StatPanel("File Information", 2);
		fileStatPanel.setLine(0, "Select a file");
		fileStatPanel.setLine(1, "0 B");
		
		//create action panel to select working directory
		workingDirButton = new JButton();
		workingDirButton.setText("...");
		workingDirButton.setBackground(Color.LIGHT_GRAY);
		
		workingDirButton.addActionListener(
        	new ActionListener() {
				@Override public void actionPerformed(ActionEvent a) {
	                //open file chooser and select a file
					JFileChooser chsr = new JFileChooser();
					chsr.setBackground(LatLock.COLOR);
					chsr.setDialogTitle("Change Directory");
					chsr.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);;
					if(chsr.showOpenDialog(getParent()) == JFileChooser.APPROVE_OPTION) {
						String dir = chsr.getSelectedFile().getPath();
						
						float size = Math.round(selectorPanel.setDirectory(dir)/10000.0f)/100.0f;
						title = dir + " - " + size + " MB - Lat";
						
						repaint();
					}
	            }
	        });
		
		//create a button to lock/unlock files
		lockButton = new JButton();
		lockButton.setText("Lock");
		lockButton.setBackground(Color.LIGHT_GRAY);
		
		lockButton.addActionListener( 
			new ActionListener() {
				@Override public void actionPerformed(ActionEvent a) {
					File f = selectorPanel.getSelectedFile();
					if(f == null) {
						System.out.println("ERROR: Decrypt failed: No file selected");
						return;
					}
					
					if(f.getName().endsWith(LAT_FILE_EXT)) {
		                //Unlock
		                try {
							decrypt(f);					
							
							System.out.println("Successfully decrypted from "+f.getName());
						} catch (IOException | NtruException e) {
							System.out.println("ERROR: Decrypt failed: "+e.getLocalizedMessage());
							e.printStackTrace();
						}
					} else {
		                //Lock
		                try {
		                	//encrypt using value of password field
							encrypt(f);
							
							System.out.println("Successfully encrypted from "+f.getName());
						} catch (IOException | NtruException e) {
							System.out.println("ERROR: Encrypt failed: "+ e.getLocalizedMessage());
							e.printStackTrace();
						}
					}
	            }
			});

		//create some padding objects
		JPanel[] padding = new JPanel[6];
		for(int i = 0; i < 6; i++) {
			padding[i] = new JPanel();
			padding[i].setBackground(LatLock.COLOR);
		}

		//create the holder panel for the bottom bar
		statHolderPanel = new JPanel();
		statHolderPanel.setLayout(new BoxLayout(statHolderPanel, BoxLayout.X_AXIS));
		statHolderPanel.setBackground(LatLock.COLOR);

		statHolderPanel.add(padding[0]);
		statHolderPanel.add(fileStatPanel);
		
		statHolderPanel.add(padding[1]);
		statHolderPanel.add(lockButton);
		
		statHolderPanel.add(padding[2]);
		statHolderPanel.add(workingDirButton);
		
		statHolderPanel.add(padding[3]);
		
		//add everything in proper order
		add(selectorPanel);
		
		add(padding[4]);
		
		add(statHolderPanel);
		
		add(padding[5]);
	}
	
	public void refresh() {
		//refresh the selector
		selectorPanel.refresh();

		//set password button text based on file type
		File f = selectorPanel.getSelectedFile();
				
		if(f != null) {
			if(f.getName().endsWith(LAT_FILE_EXT)) {
				lockButton.setText("Unlock");
			} else {
				lockButton.setText("Lock");
			}
			
			//update the statPanel
			fileStatPanel.setLine(0, f.getName());
			fileStatPanel.setLine(1, f.length() + " B");
		} else {
			fileStatPanel.setLine(0, "Select a file");
			fileStatPanel.setLine(1, "0 B");
		}
	}
}
