package latLock;

import java.awt.Color;
import java.awt.Graphics2D;
import java.io.File;

public class FileIcon {
	private static SVGGraphic fileSVG = new SVGGraphic("res/file.svg");
	
	private static final int SVG_SIZE = 75;
	private static final int SVG_PAD = 15;
	
	private File file;
	
	private int x, y;
	
	private void calcPos(int index, float width) {
		//don't recalculate if the window is too narrow
		if(width < (SVG_SIZE+SVG_PAD*2)) { return; }
		
		//calculate number of files per row
		int per_row = (int) Math.floor(width/(SVG_SIZE+SVG_PAD*2));
		
		//calculate x and y position in the grid
		int y_index = (int) Math.floor(index / (float) per_row);
		int x_index = index % per_row;
		
		//calcluate overall x, y position
		x = (SVG_SIZE+SVG_PAD*2)*x_index;
		y = (SVG_SIZE+SVG_PAD*2)*y_index;
	}
	
	public FileIcon(File file) {		
		this.file = file;  
	}
	
	public void draw(Graphics2D g, int index, float width, boolean selected) {	
		//recalculate positioning of files
		calcPos(index, width);
		
		//move to x, y
		g.translate(x+SVG_PAD, y+SVG_PAD);
		
		//draw a rectangle around the file if it's selected
		if(selected) {
			g.setColor(Color.DARK_GRAY);
			g.drawRect(0, 0, SVG_SIZE, SVG_SIZE);
		}
		
		//draw the SVG
		fileSVG.draw(g);
		
		//move to bottom of file icon
		g.translate(SVG_SIZE/2, SVG_SIZE+15);
		
		//get the filename's width and truncate if necessary.
		String name = file.getName();
		int w = g.getFontMetrics().stringWidth(name);
		
		if(w > SVG_SIZE+SVG_PAD*2) {
			name = name.substring(0, 10)+"...";
		}
		
		//get the new truncated width
		w = g.getFontMetrics().stringWidth(name);
		
		//draw the  centered filename
		g.drawString(name, -w/2, 0);
	}
	
	public File getFile() {
		return file;
	}
	
	public boolean getCollide(int mx, int my) {
		//simple box collision
		return x+SVG_PAD <= mx && mx < x+SVG_PAD+SVG_SIZE &&
				y+SVG_PAD <= my && my < y+SVG_PAD+SVG_SIZE;		
	}
}
