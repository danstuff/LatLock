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

public class SelectorPanel extends JPanel{
	private static final long serialVersionUID = 1L;

	private static final String BKG_FILE = "res/bkg.svg";
	
	private SVGGraphic svgBkg;
	
	private Vector<FileIcon> dirFiles;
	private String dir;
	
	private int selectedDirFile = 0;
	
	public SelectorPanel() {
		//create a panel that lists files
		setBackground(Color.LIGHT_GRAY);
		setPreferredSize(new Dimension(1000, 1000));

		//create background
		try {
			svgBkg = new SVGGraphic(BKG_FILE);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		//check if a file was clicked and select it
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
	
	public long setDirectory(String dir) {
		//if dir changed, clear selected file
		if(this.dir != dir) {
			selectedDirFile = 0;
		}
		
		//clear dirFiles list and set the dir
		dirFiles = new Vector<FileIcon>();
		this.dir = dir;
		
		//list all files in dir
		File d = new File(dir);
		File[] files = d.listFiles();
		
		//add all non-directories to dirFiles and add up their sizes
		long size = 0;
		
		for(int i = 0; i < files.length; i++) {
			if(!files[i].isDirectory()) {
				dirFiles.add(new FileIcon(files[i]));
				size += files[i].length();
			}
		}
		
		//return the sum of file sizes
		return size;
	}
	
	public void refresh() {
		setDirectory(dir);
		repaint();
	}
	
	public File getSelectedFile() {
		if(dirFiles.size() == 0) { return null; }
		return dirFiles.get(selectedDirFile).getFile();
	}
	
	@Override
	protected void paintComponent(Graphics graphics) {
		super.paintComponent(graphics);
		
		//enable antialiasing
		Graphics2D g = (Graphics2D) graphics.create();
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
				RenderingHints.VALUE_ANTIALIAS_ON);

		//copy original transform
		AffineTransform originalT = g.getTransform();
		
		//calculate scale factor and scale
		float sx = getWidth() / svgBkg.getWidth();
		float sy = getHeight() / svgBkg.getHeight();
		
		g.scale(sx, sy);
		
		//render background
		svgBkg.draw(g);
		
		//render files
		for(int i = 0; i < dirFiles.size(); i++) {
			g.setTransform(originalT);
			dirFiles.elementAt(i).draw(g, i, getWidth(), i == selectedDirFile);;
		}
	}
}
