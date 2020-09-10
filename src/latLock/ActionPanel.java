package latLock;

import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionListener;

import javax.swing.AbstractButton;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class ActionPanel extends JPanel{
	private static final long serialVersionUID = 1L;
	
	private JTextField header, field;
	private JButton button;

	public ActionPanel(String header_text, String button_text, boolean is_password, 
			ActionListener button_act) {
		// Set up panel size
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		
    	// Create fonts
		Font header_font = new Font("Sans-Serif", Font.PLAIN, 12);
		Font edit_font = new Font("Sans-Serif", Font.PLAIN, 14);
		
        // Create header
        header = new JTextField();
		header.setHorizontalAlignment(JTextField.LEFT);
		header.setEditable(false);
		header.setBorder(null);

		header.setFont(header_font);
		header.setText(header_text);
		
		header.setForeground(Color.WHITE);
		header.setBackground(Color.DARK_GRAY);
        
        // Create selector field
		if(is_password) {
			field = new JPasswordField();	
		} else {
			field = new JTextField();
		}
        
		field.setFont(edit_font);
		field.setToolTipText("Select a Folder");
		
		field.setBorder(null);

        // Create button
        button = new JButton(button_text);
		button.setVerticalTextPosition(AbstractButton.CENTER);
		button.setHorizontalTextPosition(AbstractButton.CENTER);
		
		button.addActionListener(button_act);
		
		button.setBackground(Color.LIGHT_GRAY);
		        
        // Create horizontal inner panel
        JPanel inner_panel = new JPanel();
        inner_panel.setLayout(new BoxLayout(inner_panel, BoxLayout.X_AXIS));

        add(header);
        
        inner_panel.add(field);
        inner_panel.add(button);

        add(inner_panel);
	}
	
	public void setValue(String t) {
		field.setText(t);
	}
	
	public String getValue() {
		return field.getText();
	}
	
	public void setButtonLabel(String l) {
		button.setText(l);
	}
}
