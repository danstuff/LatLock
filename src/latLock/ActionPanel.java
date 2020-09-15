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

public class ActionPanel extends JPanel{
	private static final long serialVersionUID = 1L;
	
	private static final int LINE_WIDTH = 200;
	private static final int LINE_HEIGHT = 10;
	
	private JTextField header, field;
	private JButton button;

	public ActionPanel(String header_text, String field_text, String button_text,
			boolean is_password, ActionListener button_act) {
		setBackground(LatLock.COLOR);
		
		// Set up panel size
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		
    	// Create fonts
		Font header_font = new Font("Sans-Serif", Font.PLAIN, 14);
		Font edit_font = new Font("Sans-Serif", Font.PLAIN, 12);
		
        // Create header
        header = new JTextField();
		header.setHorizontalAlignment(JTextField.LEFT);
		header.setEditable(false);
		header.setBorder(null);

		header.setFont(header_font);
		header.setText(header_text);
		
		header.setForeground(Color.WHITE);
		header.setBackground(LatLock.COLOR);
        
        // Create selector field
		if(is_password) {
			field = new JPasswordField();
		} else {
			field = new JTextField();
			field.setEditable(false);
			field.setBackground(LatLock.COLOR);
			field.setForeground(Color.LIGHT_GRAY);
		}

		field.setBorder(null);
		field.setFont(edit_font);
		field.setText(field_text);
		
		field.setPreferredSize(new Dimension(LINE_WIDTH, LINE_HEIGHT));

        // Create button
        button = new JButton(button_text);
		button.setVerticalTextPosition(AbstractButton.CENTER);
		button.setHorizontalTextPosition(AbstractButton.CENTER);
		//button.setFont(edit_font);
		
		button.addActionListener(button_act);
		
		button.setBackground(Color.LIGHT_GRAY);
		        
        // Create horizontal inner panel
		JPanel button_panel = new JPanel(new BorderLayout(0,0));
		button_panel.add(button);
		
        JPanel inner_panel = new JPanel();
        inner_panel.setLayout(new BoxLayout(inner_panel, BoxLayout.X_AXIS));
        
        inner_panel.setBackground(LatLock.COLOR);

        add(header);
        
        inner_panel.add(field);
        inner_panel.add(button_panel);

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
