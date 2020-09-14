package latLock;

import java.awt.Color;
import java.awt.Graphics2D;
import java.io.File;

public class LatFileIcon {
	private static LatSVG fileSVG = new LatSVG("res/file.svg");
	
	private static final int SVG_WIDTH = 150;
	private static final int SVG_HEIGHT= 150;
	
	private File file;
	
	private int x, y;
	
	private void calcPos(int index, float width) {
		if(width < SVG_WIDTH) { return; }
		
		int per_row = (int) Math.floor(width/SVG_WIDTH);
		int y_index = (int) Math.floor(index / (float) per_row);
		int x_index = index % per_row;
		
		x = SVG_WIDTH*x_index;
		y = SVG_HEIGHT*y_index;
	}
	
	public LatFileIcon(File file) {		
		this.file = file;  
	}
	
	public void draw(Graphics2D g, int index, float width, boolean selected) {	
		calcPos(index, width);
		
		g.translate(x, y);
		
		if(selected) {
			g.setColor(Color.RED);
			g.drawRect(0, 0, SVG_WIDTH, SVG_HEIGHT);
		}
		
		fileSVG.draw(g);
		
		g.translate(0,-35);
		
		g.drawString(file.getName(), 100, 200);
	}
	
	public File getFile() {
		return file;
	}
	
	public boolean getCollide(int mx, int my) {
		return x <= mx && mx < x+SVG_WIDTH &&
				y <= my && my < y+SVG_HEIGHT;		
	}
}
