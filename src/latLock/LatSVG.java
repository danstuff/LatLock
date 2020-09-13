package latLock;

import java.awt.Graphics2D;
import java.io.File;
import java.net.MalformedURLException;

import com.kitfox.svg.SVGDiagram;
import com.kitfox.svg.SVGException;
import com.kitfox.svg.SVGUniverse;

public class LatSVG {	
	private static SVGUniverse svgUni = null;
	
	private SVGDiagram svgDiag;
	
	public LatSVG(String filename) {
		try {
			if(svgUni == null) {
				svgUni = new SVGUniverse();
			}
			
			svgDiag = svgUni.getDiagram(svgUni.loadSVG(
							new File(filename).toURL()));
			
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}		
	}
	
	public void draw(Graphics2D g) {
		try {
			svgDiag.render(g);
		} catch (SVGException e) {
			e.printStackTrace();
		}
	}
	
	public float getWidth() {
		return svgDiag.getWidth();
	}
	
	public float getHeight() {
		return svgDiag.getHeight();
	}
}
