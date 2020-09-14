package latLock;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.geom.AffineTransform;
import java.io.File;
import java.util.Vector;

import javax.swing.JPanel;

public class LatSelector extends JPanel{
	private static final long serialVersionUID = 1L;

	private static final String BKG_FILE = "res/bkg.svg";
	
	private LatSVG svgBkg;
	private Vector<LatFileIcon> dirFiles;
	private int selectedDirFile = 0;
	
	public LatSelector(String dir) {
		setBackground(Color.LIGHT_GRAY);
		setPreferredSize(new Dimension(1000, 1000));

		try {
			svgBkg = new LatSVG(BKG_FILE);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		setDirectory(dir);
		
		addMouseListener(new MouseListener() {
			@Override public void mouseReleased(MouseEvent m) {}
			@Override public void mousePressed(MouseEvent m) {}
			@Override public void mouseExited(MouseEvent m) {}
			@Override public void mouseEntered(MouseEvent m) {}
			
			@Override
			public void mouseClicked(MouseEvent m) {
				int x = m.getPoint().x;
				int y = m.getPoint().y;
				
				for(int i = 0; i < dirFiles.size(); i++) {
					if(dirFiles.get(i).getCollide(x, y)) {
						selectedDirFile = i;
						repaint();
						return;
					}
				}
			}
		});
	}
	
	public void setDirectory(String dir) {
		dirFiles = new Vector<LatFileIcon>();
		
		File d = new File(dir);
		
		File[] files = d.listFiles();
		
		selectedDirFile = 0;
		
		for(int i = 0; i < files.length; i++) {
			if(!files[i].isDirectory()) {
				dirFiles.add(new LatFileIcon(files[i]));
			}
		}
	}
	
	public File getSelectedFile() {
		return dirFiles.get(selectedDirFile).getFile();
	}
	
	@Override
	protected void paintComponent(Graphics graphics) {
		super.paintComponent(graphics);
		
		Graphics2D g = (Graphics2D) graphics.create();
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
				RenderingHints.VALUE_ANTIALIAS_ON);

		AffineTransform originalT = g.getTransform();
		
		float sx = getWidth() / svgBkg.getWidth();
		float sy = getHeight() / svgBkg.getHeight();
		
		g.scale(sx, sy);
		
		svgBkg.draw(g);
		
		for(int i = 0; i < dirFiles.size(); i++) {
			g.setTransform(originalT);
			dirFiles.elementAt(i).draw(g, i, getWidth(), i == selectedDirFile);;
		}
	}
}
