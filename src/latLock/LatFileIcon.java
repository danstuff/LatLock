package latLock;

import java.awt.Color;
import java.awt.Graphics2D;
import java.io.File;

public class LatFileIcon {
	private static LatSVG fileSVG = new LatSVG("res/file.svg");
	
	private static final int SVG_SIZE = 75;
	private static final int SVG_PAD = 15;
	
	private File file;
	
	private int x, y;
	
	private void calcPos(int index, float width) {
		if(width < (SVG_SIZE+SVG_PAD*2)) { return; }
		
		int per_row = (int) Math.floor(width/(SVG_SIZE+SVG_PAD*2));
		int y_index = (int) Math.floor(index / (float) per_row);
		int x_index = index % per_row;
		
		x = (SVG_SIZE+SVG_PAD*2)*x_index;
		y = (SVG_SIZE+SVG_PAD*2)*y_index;
	}
	
	public LatFileIcon(File file) {		
		this.file = file;  
	}
	
	public void draw(Graphics2D g, int index, float width, boolean selected) {	
		calcPos(index, width);
		
		g.translate(x+SVG_PAD, y+SVG_PAD);
		
		if(selected) {
			g.setColor(Color.DARK_GRAY);
			g.drawRect(0, 0, SVG_SIZE, SVG_SIZE);
		}
		
		fileSVG.draw(g);
		
		g.translate(SVG_SIZE/2, SVG_SIZE+15);
		
		String name = file.getName();
		int w = g.getFontMetrics().stringWidth(name);
		
		if(w > SVG_SIZE+SVG_PAD*2) {
			name = name.substring(0, 10)+"...";
		}
		
		w = g.getFontMetrics().stringWidth(name);
		
		g.drawString(name, -w/2, 0);
	}
	
	public File getFile() {
		return file;
	}
	
	public boolean getCollide(int mx, int my) {
		return x+SVG_PAD <= mx && mx < x+SVG_PAD+SVG_SIZE &&
				y+SVG_PAD <= my && my < y+SVG_PAD+SVG_SIZE;		
	}
}
