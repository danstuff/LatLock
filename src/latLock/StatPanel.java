package latLock;

import java.awt.Color;
import java.awt.Font;
import java.util.Vector;

import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class StatPanel extends JPanel{
	private static final long serialVersionUID = 1L;
	
	private JTextField header;
	private Vector<JTextField> lines;
	
	public StatPanel(String header_text, int num_lines) {
		setBackground(LatLock.COLOR);
		
		// Set up panel size
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		
    	// Create fonts
		Font header_font = new Font("Sans-Serif", Font.PLAIN, 14);
		Font body_font = new Font("Sans-Serif", Font.PLAIN, 12);
		
        // Create header
        header = new JTextField();
		header.setHorizontalAlignment(JTextField.LEFT);
		header.setEditable(false);
		header.setBorder(null);

		header.setFont(header_font);
		header.setText(header_text);
		
		header.setForeground(Color.WHITE);
		header.setBackground(LatLock.COLOR);
		
        add(header);
		        
        // Create lines
        lines = new Vector<JTextField>();
        
        for(int i = 0; i < num_lines; i++) {
            JTextField line = new JTextField();
            line.setHorizontalAlignment(JTextField.LEFT);
            line.setEditable(false);
            line.setBorder(null);

            line.setFont(body_font);
            line.setText("");
    		
            line.setForeground(Color.LIGHT_GRAY);
            line.setBackground(LatLock.COLOR);
            
            lines.add(line);
        	add(lines.get(i));
        }
	}
	
	public void setLine(int num, String data) {
		lines.get(num).setText(data);
	}
}
