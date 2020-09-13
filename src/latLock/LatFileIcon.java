package latLock;

import java.awt.Graphics2D;
import java.io.File;

public class LatFileIcon {
	private static LatSVG fileSVG = new LatSVG("res/file.svg");
	
	private static final int SVG_WIDTH = 150;
	private static final int SVG_HEIGHT= 150;
	
	private File file;
	
	public LatFileIcon(File file) {		
		this.file = file;  
	}
	
	public void draw(Graphics2D g, int index, float width) {	
		if(width < SVG_WIDTH) { return; }
		
		int per_row = (int) Math.floor(width/SVG_WIDTH);
		int y_index = (int) Math.floor(index / (float) per_row);
		int x_index = index % per_row;
		
		g.translate(SVG_WIDTH*x_index, SVG_HEIGHT*y_index);
		
		fileSVG.draw(g);
		
		g.translate(0,-35);
		
		g.drawString(file.getName(), 100, 200);
	}
	
	public File getFile() {
		return file;
	}
}
