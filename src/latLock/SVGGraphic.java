package latLock;

import java.awt.Graphics2D;
import com.kitfox.svg.SVGDiagram;
import com.kitfox.svg.SVGException;
import com.kitfox.svg.SVGUniverse;

public class SVGGraphic {	
	private static SVGUniverse svgUni = null;
	
	private SVGDiagram svgDiag;
	
	public SVGGraphic(String filename) {
		try {
			//create a universe if one doesn't already exist
			if(svgUni == null) {
				svgUni = new SVGUniverse();
			}
			
			//load a diagram using that universe
			svgDiag = svgUni.getDiagram(svgUni.loadSVG(
							this.getClass().getResource(filename)));
			
		} catch (Exception e) {
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
