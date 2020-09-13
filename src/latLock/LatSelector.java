package latLock;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.AffineTransform;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Vector;

import javax.swing.JPanel;

import com.kitfox.svg.SVGDiagram;
import com.kitfox.svg.SVGException;
import com.kitfox.svg.SVGUniverse;
import com.kitfox.svg.app.beans.SVGIcon;
import com.kitfox.svg.app.beans.SVGPanel;

public class LatSelector extends JPanel{
	private static final long serialVersionUID = 1L;

	private static final String BKG_FILE = "res/bkg.svg";
	private static final String FILE_FILE = "res/file.svg";
	
	private SVGUniverse svgUni;

	private SVGDiagram svgBkg;
	private SVGDiagram svgFile;
	
	private Vector<File> dirFiles;
	
	public LatSelector() {
		setBackground(Color.LIGHT_GRAY);
		setPreferredSize(new Dimension(1000, 1000));

		File b = new File(BKG_FILE);
		File f = new File(FILE_FILE);
		
		svgUni = new SVGUniverse();
		
		try {
			svgBkg = svgUni.getDiagram(svgUni.loadSVG(b.toURL()));
			svgFile = svgUni.getDiagram(svgUni.loadSVG(f.toURL()));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void setDirectory(String dir) {
		dirFiles = new Vector<File>();
		
		File d = new File(dir);
		
		File[] files = d.listFiles();
		
		for(int i = 0; i < files.length; i++) {
			if(files[i].getName().endsWith(LatLock.LAT_FILE_EXT)) {
				dirFiles.add(files[i]);
			}
		}
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
		
		try {
			svgBkg.render(g);
		} catch (SVGException e) {
			e.printStackTrace();
		}
		
		g.setTransform(originalT);

		try {
			svgFile.render(g);
		} catch (SVGException e) {
			e.printStackTrace();
		}
		
		g.drawString("FILENAME", 100, 200);
	}
}
